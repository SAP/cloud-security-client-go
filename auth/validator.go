// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/sap-staging/cloud-security-client-go/oidcclient"
	"net/url"
	"strings"
)

func (m *AuthMiddleware) ParseAndValidateJWT(rawToken string) (*jwt.Token, error) {
	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		return nil, err
	}
	token.Signature = parts[2]

	// get keyset
	keySet, err := m.getKeySet(token)
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

	token.Valid = true
	return token, nil
}

func (m *AuthMiddleware) verifySignature(t *jwt.Token, ks *oidcclient.RemoteKeySet) error {
	jwks, err := ks.GetKeys()
	if err != nil {
		return wrapError(&jwt.UnverfiableTokenError{Message: "failed to fetch token keys from remote"}, err)
	}
	if len(jwks) == 0 {
		return &jwt.UnverfiableTokenError{Message: "remote returned no jwk to verify the token"}
	}

	var jwk *oidcclient.JSONWebKey

	if kid := t.Header[propKeyID]; kid != nil {
		for i, key := range jwks {
			if key.Kid == kid {
				jwk = jwks[i]
				break
			}

			return &jwt.UnverfiableTokenError{Message: "kid id specified in token not presented by remote"}
		}
	} else if len(jwks) == 1 {
		jwk = jwks[0]
	} else {
		return &jwt.UnverfiableTokenError{Message: "no kid specified in token and more than one verification key available"}
	}

	// join token together again, as t.Raw does not contain signature
	if err := t.Method.Verify(strings.TrimSuffix(t.Raw, "."+t.Signature), t.Signature, jwk.Key); err != nil {
		// invalid
		return wrapError(&jwt.InvalidSignatureError{}, err)
	}
	return nil
}

func (m *AuthMiddleware) validateClaims(t *jwt.Token, ks *oidcclient.RemoteKeySet) error {
	validationHelper := jwt.NewValidationHelper(
		jwt.WithAudience(m.options.OAuthConfig.GetClientID()),
		jwt.WithIssuer(ks.ProviderJSON.Issuer))

	err := t.Claims.(*OIDCClaims).Valid(validationHelper)

	return err
}

func (m *AuthMiddleware) getKeySet(t *jwt.Token) (*oidcclient.RemoteKeySet, error) {
	claims, ok := t.Claims.(*OIDCClaims)
	if !ok {
		return nil, &jwt.UnverfiableTokenError{
			Message: fmt.Sprintf("internal validation error during type assertion: expected *OIDCClaims, got %T", t.Claims)}
	}

	iss := claims.Issuer
	issURI, err := url.ParseRequestURI(iss)
	if err != nil {
		return nil, fmt.Errorf("unable to parse issuer URI: %s", iss)
	}

	bindingIssURI, err := url.ParseRequestURI(m.options.OAuthConfig.GetURL())
	if err != nil {
		return nil, fmt.Errorf("unable to parse issuer URI: %s", iss)
	}

	// TODO: replace this check later against domain property from binding to enable multi tenancy support
	if bindingIssURI.Hostname() != issURI.Hostname() {
		return nil, &jwt.UnverfiableTokenError{Message: "token is issued by unsupported oauth server"}
	}

	var keySet *oidcclient.RemoteKeySet
	if keySet, ok = m.saasKeySet[iss]; !ok {
		newKeySet, err, _ := m.sf.Do(iss, func() (i interface{}, err error) {

			set, err := oidcclient.NewKeySet(m.options.HTTPClient, issURI)
			return set, err
		})

		if err != nil {
			return nil, wrapError(&jwt.UnverfiableTokenError{Message: "unable to build remote keyset"}, err)
		}
		keySet = newKeySet.(*oidcclient.RemoteKeySet)
		m.saasKeySet[iss] = keySet

	}
	return keySet, nil
}

func wrapError(a, b error) error {
	if b == nil {
		return a
	}
	if a == nil {
		return b
	}

	type iErrorWrapper interface {
		Wrap(error)
	}
	if w, ok := a.(iErrorWrapper); ok {
		w.Wrap(b)
	}
	return a
}
