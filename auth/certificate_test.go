// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/x-forwarded-client-cert.txt
var derCertFromFile string

func TestCertificate(t *testing.T) {
	t.Run("newCertificate() returns nil when no certificate is given", func(t *testing.T) {
		cert, err := newCertificate("")
		assert.Nil(t, cert)
		assert.Nil(t, err)
	})

	t.Run("newCertificate() fails when DER certificate is corrupt", func(t *testing.T) {
		cert, err := newCertificate("abc123")
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "cannot base64 decode certificate header:")
	})

	t.Run("newCertificate() fails when PEM certificate is corrupt", func(t *testing.T) {
		cert, err := newCertificate("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQxVENDQXIyZ0F3SUJBZ0lNSUxvRXNuTFFCdQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t")
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "cannot decode PEM formatted certificate header:")
	})

	t.Run("GetThumbprint() for PEM formatted cert", func(t *testing.T) {
		cert, _ := newCertificate(convertToPEM(t, derCertFromFile))
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
	})

	t.Run("GetThumbprint() for DER formatted cert", func(t *testing.T) {
		cert, _ := newCertificate(derCertFromFile)
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
	})
}

func generateToken(t *testing.T, claimCnfMemberX5tValue string) Token {
	token := jwt.New()
	cnfClaim := map[string]interface{}{
		claimCnfMemberX5t: claimCnfMemberX5tValue,
	}
	err := token.Set(claimCnf, cnfClaim)
	require.NoError(t, err, "Failed to create token: %v", err)

	return IDToken{jwtToken: token}
}

func convertToPEM(t *testing.T, derCert string) string {
	x509Cert, err := newCertificate(derCert)
	require.NoError(t, err, "failed to create certificate: %v", err)

	bytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.x509Cert.Raw})
	return base64.StdEncoding.EncodeToString(bytes)
}

func generateDERCert() string {
	key, _ := rsa.GenerateKey(rand.Reader, 512) //nolint:gosec

	issuerName := pkix.Name{
		Organization: []string{"my-issuer-org"},
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(125),
		Subject: pkix.Name{
			Organization: []string{"my-subject-org"},
		},
		Issuer: issuerName,
	}
	issTemplate := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      issuerName,
		Issuer:       issuerName,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &issTemplate, &key.PublicKey, key)

	return base64.StdEncoding.EncodeToString(derBytes)
}
