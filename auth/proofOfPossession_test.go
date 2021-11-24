// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

var derCertGenerated = generateDERCert()

func TestProofOfPossession_parseAndValidateCertificate_edgeCases(t *testing.T) {
	t.Run("validateCertificate() fails when no cert is given", func(t *testing.T) {
		err := ValidateX5tThumbprint(nil, generateToken(t, "abc"))
		assert.Equal(t, "there is no x509 client certificate provided", err.Error())
	})

	t.Run("validateCertificate() fails when no token is given", func(t *testing.T) {
		x509Cert, err := newCertificate(derCertGenerated)
		require.NoError(t, err, "Failed to parse cert header: %v", err)
		err = ValidateX5tThumbprint(x509Cert, nil)
		assert.Equal(t, "there is no token provided", err.Error())
	})

	t.Run("validateCertificate() fails when cert does not match x5t", func(t *testing.T) {
		x509Cert, err := newCertificate(derCertGenerated)
		require.NoError(t, err, "Failed to parse cert header: %v", err)
		err = ValidateX5tThumbprint(x509Cert, generateToken(t, "abc"))
		assert.Equal(t, "token thumbprint confirmation failed", err.Error())
	})
}

func TestProofOfPossession_validateX5tThumbprint_edgeCases(t *testing.T) {
	t.Run("ValidateX5tThumbprint() fails when no cert is given", func(t *testing.T) {
		err := ValidateX5tThumbprint(nil, generateToken(t, "abc"))
		assert.Equal(t, "there is no x509 client certificate provided", err.Error())
	})

	t.Run("ValidateX5tThumbprint() fails when no token is given", func(t *testing.T) {
		x509Cert, err := newCertificate(derCertGenerated)
		require.NoError(t, err, "Failed to parse cert header: %v", err)
		err = ValidateX5tThumbprint(x509Cert, nil)
		assert.Equal(t, "there is no token provided", err.Error())
	})
}

func TestProofOfPossession_validateX5tThumbprint(t *testing.T) {
	tests := []struct {
		name              string
		claimCnfMemberX5t string
		cert              string
		pemEncoded        bool
		expectedErrMsg    string // in case of empty string no error is expected
	}{
		{
			name:              "x5t should match with DER certificate (HAProxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			cert:              derCertFromFile,
			pemEncoded:        false,
			expectedErrMsg:    "",
		}, {
			name:              "x5t should match with PEM certificate (apache proxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			cert:              derCertFromFile,
			pemEncoded:        true,
			expectedErrMsg:    "",
		}, {
			name:              "expect error when x5t does not match with generated DER certificate (HAProxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			cert:              derCertGenerated,
			pemEncoded:        false,
			expectedErrMsg:    "token thumbprint confirmation failed",
		}, {
			name:              "expect error when x5t does not match with generated PEM certificate (apache proxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			cert:              derCertGenerated,
			pemEncoded:        true,
			expectedErrMsg:    "token thumbprint confirmation failed",
		}, {
			name:              "expect error when x5t is empty",
			claimCnfMemberX5t: "",
			cert:              derCertGenerated,
			pemEncoded:        false,
			expectedErrMsg:    "token provides no cnf member for thumbprint confirmation",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.cert
			if tt.pemEncoded == true {
				cert = convertToPEM(t, tt.cert)
			}
			x509cert, err := newCertificate(cert)
			require.NoError(t, err, "Failed to validate client cert with token cnf thumbprint: %v", err)

			err = ValidateX5tThumbprint(x509cert, generateToken(t, tt.claimCnfMemberX5t))
			if tt.expectedErrMsg != "" {
				assert.Equal(t, tt.expectedErrMsg, err.Error())
			} else {
				require.NoError(t, err, "Failed to validate client cert with token cnf thumbprint: %v", err)
			}
		})
	}
}

func generateToken(t *testing.T, claimCnfMemberX5tValue string) Token {
	token := jwt.New()
	cnfClaim := map[string]interface{}{
		claimCnfMemberX5t: claimCnfMemberX5tValue,
	}
	err := token.Set(claimCnf, cnfClaim)
	require.NoError(t, err, "Failed to create token: %v", err)

	return stdToken{jwtToken: token}
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
