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
	"os"
	"path"
	"testing"
)

func TestProofOfPossession_ParseCertHeader_edgeCases(t *testing.T) {
	t.Run("ParseCertHeader() fails when no certificate is given", func(t *testing.T) {
		_, err := ParseCertHeader("")
		assert.Equal(t, "there is no certificate header provided", err.Error())
	})

	t.Run("ParseCertHeader() fails when DER certificate is corrupt", func(t *testing.T) {
		_, err := ParseCertHeader("abc123")
		assert.Contains(t, err.Error(), "cannot base64 decode certificate header:")
	})

	t.Run("ParseCertHeader() fails when PEM certificate is corrupt", func(t *testing.T) {
		_, err := ParseCertHeader("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQxVENDQXIyZ0F3SUJBZ0lNSUxvRXNuTFFCdQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t")
		assert.Contains(t, err.Error(), "cannot decode PEM formatted certificate header:")
	})
}

func TestProofOfPossession_validateX5tThumbprint_edgeCases(t *testing.T) {
	t.Run("ValidateX5tThumbprint() fails when no cert is given", func(t *testing.T) {
		err := ValidateX5tThumbprint(nil, createToken(t, "abc"))
		assert.Equal(t, "there is no x509 client certificate provided", err.Error())
	})

	t.Run("ValidateX5tThumbprint() fails when no token is given", func(t *testing.T) {
		x509Cert, err := ParseCertHeader(generateCert(t, "test-issuer-org", "test-subject-org", false))
		require.NoError(t, err, "Failed to parse cert header: %v", err)
		err = ValidateX5tThumbprint(x509Cert, nil)
		assert.Equal(t, "there is no token provided", err.Error())
	})
}

func TestProofOfPossession_validateX5tThumbprint(t *testing.T) {
	tests := []struct {
		name              string
		claimCnfMemberX5t string
		certFile          string // in case of empty string it gets generated
		pemEncoded        bool
		expectedErrMsg    string // in case of empty string no error is expected
	}{
		{
			name:              "x5t should match with DER certificate (go router)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			certFile:          "x-forwarded-client-cert.txt",
			pemEncoded:        false,
			expectedErrMsg:    "",
		}, {
			name:              "x5t should match with PEM certificate (apache proxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			certFile:          "x-forwarded-client-cert.txt",
			pemEncoded:        true,
			expectedErrMsg:    "",
		}, {
			name:              "expect error when x5t does not match with generated DER certificate (go router)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			certFile:          "",
			pemEncoded:        false,
			expectedErrMsg:    "token thumbprint confirmation failed",
		}, {
			name:              "expect error when x5t does not match with generated PEM certificate (apache proxy)",
			claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM",
			certFile:          "",
			pemEncoded:        true,
			expectedErrMsg:    "token thumbprint confirmation failed",
		}, {
			name:              "expect error when x5t is empty",
			claimCnfMemberX5t: "",
			certFile:          "",
			pemEncoded:        false,
			expectedErrMsg:    "token provides no cnf member for thumbprint confirmation",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var cert string
			if tt.certFile == "" {
				cert = generateCert(t, "test-issuer-org", "test-subject-org", tt.pemEncoded)
			} else {
				cert = readCert(t, tt.certFile, tt.pemEncoded)
			}
			x509cert, err := ParseCertHeader(cert)
			require.NoError(t, err, "Failed to validate client cert with token cnf thumbprint: %v", err)

			err = ValidateX5tThumbprint(x509cert, createToken(t, tt.claimCnfMemberX5t))
			if tt.expectedErrMsg != "" {
				assert.Equal(t, tt.expectedErrMsg, err.Error())
			} else {
				require.NoError(t, err, "Failed to validate client cert with token cnf thumbprint: %v", err)
			}
		})
	}
}

func createToken(t *testing.T, claimCnfMemberX5tValue string) Token {
	token := jwt.New()
	cnfClaim := map[string]interface{}{
		claimCnfMemberX5t: claimCnfMemberX5tValue,
	}
	err := token.Set(claimCnf, cnfClaim)
	require.NoError(t, err, "Failed to create token: %v", err)

	return stdToken{jwtToken: token}
}

func readCert(t *testing.T, fileName string, pemEncoded bool) string {
	pwd, _ := os.Getwd()
	certFilePath := path.Join(pwd, "testdata", fileName)
	certificate, err := os.ReadFile(certFilePath)
	require.NoError(t, err, "Failed to read certificate from %v: %v", certFilePath, err)

	x509Cert, err := ParseCertHeader(string(certificate))
	require.NoError(t, err, "failed to create certificate: %v", err)

	return encodeDERBytes(x509Cert.Raw, pemEncoded)
}

func generateCert(t *testing.T, issuerOrg, subjectOrg string, pemEncoded bool) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "")

	issuerName := pkix.Name{
		Organization: []string{issuerOrg},
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(125),
		Subject: pkix.Name{
			Organization: []string{subjectOrg},
		},
		Issuer: issuerName,
	}
	issTemplate := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      issuerName,
		Issuer:       issuerName,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issTemplate, &key.PublicKey, key)
	require.NoError(t, err, "failed to generate certificate: %v", err)

	return encodeDERBytes(derBytes, pemEncoded)
}

func encodeDERBytes(derBytes []byte, pemEncoded bool) string {
	if pemEncoded {
		derBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	}
	return base64.StdEncoding.EncodeToString(derBytes)
}
