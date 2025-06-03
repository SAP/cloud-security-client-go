// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/sap/cloud-security-client-go/auth"
)

//go:embed testdata/privateTestingKey.pem
var dummyKey string

// NewTokenFromClaims creates a Token from claims. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewTokenFromClaims(claims map[string]interface{}) (auth.Token, error) {
	jwtToken := jwt.New()
	for key, value := range claims {
		err := jwtToken.Set(key, value)
		if err != nil {
			return auth.Token{}, err
		}
	}

	block, _ := pem.Decode([]byte(strings.ReplaceAll(dummyKey, "TESTING KEY", "PRIVATE KEY")))
	if block == nil {
		return auth.Token{}, fmt.Errorf("failed to parse PEM block containing dummyKey")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return auth.Token{}, fmt.Errorf("unable to create mock server: error generating rsa key: %w", err)
	}

	signedJwt, err := jwt.Sign(jwtToken, jwa.RS256, rsaKey)
	if err != nil {
		return auth.Token{}, fmt.Errorf("error signing token: %w", err)
	}

	return auth.NewToken(string(signedJwt))
}
