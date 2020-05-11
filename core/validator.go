package core

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

func (m *AuthMiddleware) ValidateJWT(rawToken string) (*jwt.Token, error) {
	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		return nil, err
	}
	token.Signature = parts[2]

	vErr := &jwt.ValidationError{}

	// verify claims
	if err := m.validateClaims(token); err != nil {
		vErr = err
		return nil, fmt.Errorf("claim check failed: %v", err)
	}

	// verify signature
	if err = m.verifySignature(token); err != nil {
		vErr.Inner = err
		vErr.Errors |= jwt.ValidationErrorSignatureInvalid
		return nil, fmt.Errorf("signature validation failed: %w", vErr)
	}

	if token.Valid = vErr.Errors == 0; token.Valid {
		return token, nil
	}

	return nil, err
}

func (m *AuthMiddleware) verifySignature(t *jwt.Token) error {
	claims, ok := t.Claims.(*OIDCClaims)
	if !ok {
		return fmt.Errorf("unable to assert claim type: expected *OIDCClaims, got %T", t.Claims)
	}
	iss := claims.Issuer
	var keySet *remoteKeySet
	if keySet, ok = m.saasKeySet[iss]; !ok {
		newKeySet, err, _ := m.sf.Do(iss, func() (i interface{}, err error) {
			set, err := newKeySet(m.options.HttpClient, iss, m.options.OAuthConfig)
			m.saasKeySet[iss] = set
			return set, err
		})

		if err != nil {
			return fmt.Errorf("unable to build remote keyset: %w", err)
		}
		keySet = newKeySet.(*remoteKeySet)
	}

	jwks, err := keySet.GetKeys()
	if err != nil {
		return fmt.Errorf("failed to fetch token keys from remote: %w", err)
	}
	if len(jwks) > 0 {
		if t.Header[KEY_ID] == nil && len(jwks) != 1 {
			return errors.New("no kid specified in token and more than one verification key available")
		}
		jwk := jwks[0]
		// join token together again, as t.Raw does not contain signature
		if err := t.Method.Verify(strings.TrimSuffix(t.Raw, "."+t.Signature), t.Signature, jwk.Key); err == nil {
			// valid
			return nil
		}
	}
	return errors.New("failed to verify token signature")
}

func (m *AuthMiddleware) validateClaims(t *jwt.Token) *jwt.ValidationError {
	vErr := &jwt.ValidationError{}
	now := time.Now().Unix()
	claims := t.Claims.(*OIDCClaims)

	if claims.VerifyExpiresAt(now, true) == false {
		delta := time.Unix(now, 0).Sub(time.Unix(claims.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if claims.VerifyIssuedAt(now, true) == false {
		vErr.Inner = fmt.Errorf("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if claims.VerifyNotBefore(now, true) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if claims.VerifyIssuer(m.options.OAuthConfig.GetURL(), true) == false {
		vErr.Inner = fmt.Errorf("token issuer does not match configured oauth server")
		vErr.Errors |= jwt.ValidationErrorIssuer
	}

	if claims.VerifyAudience(m.options.OAuthConfig.GetClientID(), true) == false {
		vErr.Inner = fmt.Errorf("token audience does not cotain this client")
		vErr.Errors |= jwt.ValidationErrorAudience
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}
