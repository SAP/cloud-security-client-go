// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/sap/cloud-security-client-go/oidcclient"
	"net/url"
	"strings"
	"time"
)

// parseAndValidateJWT parses the token into its claims, verifies the claims and verifies the signature
func (m *Middleware) parseAndValidateJWT(rawToken string) (*jwt.Token, error) {
	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		return nil, err
	}
	token.Signature = parts[2]

	// get keyset
	keySet, err := m.getOIDCTenant(token)
	if err != nil {
		return nil, err
	}

	// verify claims
	if err := m.validateClaims(token, keySet); err != nil {
		return nil, err
	}

	// verify signature
	if err = m.verifySignature(token, keySet); err != nil {
		return nil, err
	}

	mapClaims, _, err := m.parser.ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	token.Claims.(*OIDCClaims).mapClaims = mapClaims.Claims.(jwt.MapClaims)

	token.Valid = true
	return token, nil
}

func (m *Middleware) verifySignature(t *jwt.Token, ks *oidcclient.OIDCTenant) error {
	jwks, err := ks.GetJWKs()
	if err != nil {
		return fmt.Errorf("token is unverifiable: failed to fetch token keys from remote: %v", err)
	}
	if len(jwks) == 0 {
		return fmt.Errorf("token is unverifiable: remote returned no jwk to verify the token")
	}

	var jwk *oidcclient.JSONWebKey

	if kid := t.Header[propKeyID]; kid != nil {
		for _, key := range jwks {
			if key.Kid == kid {
				jwk = key
				break
			}
		}
		if jwk == nil {
			return fmt.Errorf("token is unverifiable: kid id specified in token not presented by remote")
		}
	} else if len(jwks) == 1 {
		jwk = jwks[0]
	} else {
		return fmt.Errorf("token is unverifiable: no kid specified in token and more than one verification key available")
	}

	// join token together again, as t.Raw does not contain signature
	if err := t.Method.Verify(strings.TrimSuffix(t.Raw, "."+t.Signature), t.Signature, jwk.Key); err != nil {
		// invalid
		return fmt.Errorf("token signature is invalid: %v", err)
	}
	return nil
}

func (m *Middleware) validateClaims(t *jwt.Token, ks *oidcclient.OIDCTenant) error {
	c := t.Claims.(*OIDCClaims)

	if c.ExpiresAt == nil {
		return fmt.Errorf("token is unverifiable: expiration time (exp) is unavailable")
	}
	validationHelper := jwt.NewValidationHelper(
		jwt.WithAudience(m.oAuthConfig.GetClientID()),
		jwt.WithIssuer(ks.ProviderJSON.Issuer),
		jwt.WithLeeway(1*time.Minute),
	)

	err := c.Valid(validationHelper)

	return err
}

func (m *Middleware) getOIDCTenant(t *jwt.Token) (*oidcclient.OIDCTenant, error) {
	claims, ok := t.Claims.(*OIDCClaims)
	if !ok {
		return nil, fmt.Errorf("token is unverifiable: internal validation error during type assertion: expected *OIDCClaims, got %T", t.Claims)
	}

	iss := claims.Issuer
	issURI, err := url.Parse(iss)
	if err != nil {
		return nil, fmt.Errorf("unable to parse issuer URI: %s", iss)
	}

	if !strings.HasSuffix(issURI.Host, m.oAuthConfig.GetDomain()) {
		return nil, fmt.Errorf("token is unverifiable: token is issued by unknown oauth server: domain must end with %v", m.oAuthConfig.GetDomain())
	}

	oidcTenant, exp, found := m.oidcTenants.GetWithExpiration(iss)
	if !found || time.Now().After(exp) {
		newKeySet, err, _ := m.sf.Do(iss, func() (i interface{}, err error) {
			set, err := oidcclient.NewOIDCTenant(m.options.HTTPClient, issURI)
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
