// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/sap/cloud-security-client-go/auth"
)

//nolint:gosec // dummy key for tests
const dummyKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAK6NtAzlUO1vwBq278cYXXQ4jgVqkE0hoHrfZ0oo4BMoZOoLc0Vx
YONmJypYVHzR8sedHBlIkrOrx6Ea/Y+CgSMCAwEAAQJAN7rOTX+5gtU3BFB75ZkF
3WFhFqGbSMT/s7s4Axlh0TuBX9l9iE4cPrP3Y07C9YC8x3yFazVzcss8KcaZ6t2E
IQIhANGqXikWfc6vSWHmSeCVlFuFSADG52M5TGZ+Tdrjo5P1AiEA1SDofTRv3pZh
HOAlR4+xQTi5eDYbUSUjDOZHY4vrqbcCIQCal2WqIf1NIg2Xc7dRMrka6iD3AbGm
hZ8Bi2tYU7RO6QIhAIerGROKa6PvagYtkM2K5LS13SpultkCoNs3Qz5U9UDlAiBV
Tng71Rpsh0wIADfO0lwYrZpjJXk5jYiYUpq72chIiw==
-----END RSA PRIVATE KEY-----
`

// NewTokenFromClaims creates a Token from claims. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewTokenFromClaims(claims map[string]interface{}) (auth.Token, error) {
	jwtToken := jwt.New()
	for key, value := range claims {
		err := jwtToken.Set(key, value)
		if err != nil {
			return auth.Token{}, err
		}
	}

	block, _ := pem.Decode([]byte(dummyKey))
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
