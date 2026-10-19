// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/sap/cloud-security-client-go/oidcclient"
)

// ParseAndValidateJWT parses the token into its claims, verifies the claims and verifies the signature.
//
// When X5T or proof token validation is enabled, use AuthenticateWithProofOfPossession instead so the
// forwarded client certificate can be validated together with the token.
func (m *Middleware) ParseAndValidateJWT(rawToken string) (Token, error) {
	token, _, err := m.parseAndValidateJWT(rawToken, "")
	return token, err
}

func (m *Middleware) parseAndValidateJWT(rawToken, clientCertificateHeader string) (Token, *Certificate, error) {
	token, err := NewToken(rawToken)
	if err != nil {
		return Token{}, nil, err
	}

	proofTokenCheckRequired := m.options.Validation.ProofToken && len(token.Audience()) > 1
	cert, err := newCertificate(clientCertificateHeader)
	if err != nil {
		return Token{}, nil, err
	}
	if (m.options.Validation.X5T || proofTokenCheckRequired) && cert == nil {
		return Token{}, nil, ErrNoClientCert
	}

	// get keyset
	keySet, err := m.getOIDCTenant(token.Issuer(), token.CustomIssuer())
	if err != nil {
		return Token{}, nil, err
	}

	// verify claims
	if err := m.validateClaims(token, keySet); err != nil {
		return Token{}, nil, err
	}

	// verify signature
	servicePlans, err := m.verifySignature(token, keySet, proofTokenCheckRequired, cert)
	if err != nil {
		return Token{}, nil, err
	}

	if m.options.Validation.X5T {
		if err := validateCertificate(cert, token); err != nil {
			return Token{}, nil, err
		}
	}
	if proofTokenCheckRequired {
		token.servicePlans = servicePlans
	}

	return token, cert, nil
}

func (m *Middleware) verifySignature(t Token, keySet *oidcclient.OIDCTenant, proofTokenCheckRequired bool, clientCertificate *Certificate) ([]string, error) {
	headers, err := getHeaders(t.TokenValue())
	if err != nil {
		return nil, err
	}
	alg := headers.Algorithm()

	// fail early to avoid another parsing of encoded token
	if alg == "" {
		return nil, errors.New("alg is missing from jwt header")
	}

	// parse and verify signature
	jwksRequest := oidcclient.JWKsRequest{
		ClientInfo: oidcclient.ClientInfo{
			ClientID: m.identity.GetClientID(),
			AppTID:   t.AppTID(),
			Azp:      t.Azp(),
		},
		AzpAppTID: t.AzpAppTID(),
	}
	if proofTokenCheckRequired {
		jwksRequest.ClientCertificate = clientCertificate.normalizedPEM()
	}
	jwksResponse, err := keySet.GetJWKsForRequest(jwksRequest)
	if err != nil {
		return nil, err
	}
	_, err = jwt.ParseString(t.TokenValue(), jwt.WithKeySet(jwksResponse.KeySet), jwt.UseDefaultKey(true))
	if err != nil {
		return nil, err
	}
	return jwksResponse.ServicePlans, nil
}

func getHeaders(encodedToken string) (jws.Headers, error) {
	msg, err := jws.Parse([]byte(encodedToken))
	if err != nil {
		return nil, err
	}

	return msg.Signatures()[0].ProtectedHeaders(), nil
}

func (m *Middleware) validateClaims(t Token, ks *oidcclient.OIDCTenant) error { // performing IsExpired check, because dgriljalva jwt.Validate() doesn't fail on missing 'exp' claim
	// performing IsExpired check, because lestrrat-go jwt.Validate() doesn't fail on missing 'exp' claim
	if t.IsExpired() {
		return fmt.Errorf("token is expired, exp: %v", t.Expiration())
	}
	err := jwt.Validate(t.getJwtToken(),
		jwt.WithAudience(m.identity.GetClientID()),
		jwt.WithIssuer(ks.ProviderJSON.Issuer),
		jwt.WithAcceptableSkew(1*time.Minute)) // to keep leeway in sync with Token.IsExpired

	if err != nil {
		return fmt.Errorf("claim validation failed: %v", err)
	}
	return nil
}

// getOIDCTenant returns an OIDC Tenant with discovered .well-known/openid-configuration.
//
// issuer is the trusted ias issuer with SAP domain of the incoming token (token.Issuer())
//
// customIssuer represents the custom issuer of the incoming token if given (token.CustomIssuer())
func (m *Middleware) getOIDCTenant(issuer, customIssuer string) (*oidcclient.OIDCTenant, error) {
	issHost, err := m.verifyIssuer(issuer)
	if err != nil {
		return nil, err
	}

	tokenIssuer := customIssuer
	if customIssuer == "" {
		tokenIssuer = issuer
	}

	oidcTenant, exp, found := m.oidcTenants.GetWithExpiration(issuer)
	// redo discovery if not found, cache expired, or tokenIssuer is not the same as Issuer on providerJSON (e.g. custom domain config just changed for that tenant)
	if !found || time.Now().After(exp) || oidcTenant.(*oidcclient.OIDCTenant).ProviderJSON.Issuer != tokenIssuer {
		newKeySet, err, _ := m.sf.Do(issuer, func() (i interface{}, err error) {
			set, err := oidcclient.NewOIDCTenant(m.options.HTTPClient, issHost)
			return set, err
		})

		if err != nil {
			return nil, fmt.Errorf("token is unverifiable: unable to perform oidc discovery: %v", err)
		}
		oidcTenant = newKeySet.(*oidcclient.OIDCTenant)
		m.oidcTenants.SetDefault(oidcTenant.(*oidcclient.OIDCTenant).ProviderJSON.Issuer, oidcTenant)
	}
	return oidcTenant.(*oidcclient.OIDCTenant), nil
}

func (m *Middleware) verifyIssuer(issuer string) (issuerHost string, err error) {
	// issuer must be a host or https url
	issuerHost = strings.TrimPrefix(issuer, "https://")

	doesMatch, err := matchesDomain(issuerHost, m.identity.GetDomains())
	if err != nil {
		return "", fmt.Errorf("error matching domain: %v", err)
	}
	if !doesMatch {
		return "", fmt.Errorf("token is unverifiable: unknown server (domain doesn't match)")
	}

	return issuerHost, nil
}

func matchesDomain(hostname string, domains []string) (bool, error) {
	for _, domain := range domains {
		if !strings.HasSuffix(hostname, domain) {
			continue
		}
		// hostname matches exactly trusted domain
		if hostname == domain {
			return true, nil
		}
		isValid, regexErr := isValidSubDomain(hostname, domain)
		if regexErr != nil {
			return false, regexErr
		}
		if isValid {
			return true, nil
		}
	}
	return false, nil
}

// isValidSubDomain additionally check subdomain because "my-accounts400.ondemand.com"
// does match Suffix, but should not be allowed
// additionally it returns false if hostname contains paths like /foo or ?test=true
func isValidSubDomain(hostname, domain string) (bool, error) {
	validSubdomainPattern := "^[a-zA-Z0-9-]{1,63}\\." + regexp.QuoteMeta(domain) + "$"
	return regexp.MatchString(validSubdomainPattern, hostname)
}
