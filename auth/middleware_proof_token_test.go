// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sap/cloud-security-client-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateWithProofOfPossession_ProofTokenValidation(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	require.NoError(t, err)
	defer mockServer.Server.Close()

	clientCertificateHeader := `By=spiffe://proxy;Hash=abc;Cert="` + url.PathEscape(certificatePEM(t, derCertFromFile)) + `"`
	clientCertificate, err := newCertificate(clientCertificateHeader)
	require.NoError(t, err)
	mockServer.ProofTokenCertificate = clientCertificate.normalizedPEM()
	mockServer.ProofTokenServicePlans = []string{"standard", "premium"}
	middleware := NewMiddleware(mockServer.Config, Options{
		HTTPClient: mockServer.Server.Client(),
		Validation: ValidationOptions{ProofToken: true},
	})
	multiAudienceToken := signProofToken(t, mockServer, mockServer.Config.ClientID, "provided-api")

	t.Run("rejects a multi-audience token without a client certificate", func(t *testing.T) {
		req := proofTokenRequest(multiAudienceToken, "")

		_, _, err := middleware.AuthenticateWithProofOfPossession(req)

		assert.ErrorIs(t, err, ErrNoClientCert)
		assert.Zero(t, mockServer.JWKsHitCounter)
	})

	t.Run("validates a multi-audience token online and exposes the consumer service plans", func(t *testing.T) {
		req := proofTokenRequest(multiAudienceToken, clientCertificateHeader)

		token, cert, err := middleware.AuthenticateWithProofOfPossession(req)

		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, []string{"standard", "premium"}, token.ServicePlans())
		plans := token.ServicePlans()
		plans[0] = "modified"
		assert.Equal(t, []string{"standard", "premium"}, token.ServicePlans())
		assert.Equal(t, clientCertificate.normalizedPEM(), mockServer.LastJWKsRequestHeader.Get("x-client_cert"))
		assert.Equal(t, "consumer-client", mockServer.LastJWKsRequestHeader.Get("x-azp"))
		assert.Equal(t, "consumer-app-tid", mockServer.LastJWKsRequestHeader.Get("x-azp_app_tid"))
		assert.Equal(t, mockServer.Config.ClientID, mockServer.LastJWKsRequestHeader.Get("x-client_id"))
		assert.Equal(t, mockServer.DefaultClaims().AppTID, mockServer.LastJWKsRequestHeader.Get("x-app_tid"))

		cachedToken, _, err := middleware.AuthenticateWithProofOfPossession(req)
		require.NoError(t, err)
		assert.Equal(t, []string{"standard", "premium"}, cachedToken.ServicePlans())
		assert.Equal(t, 1, mockServer.JWKsHitCounter)
	})

	t.Run("does not reuse a proof token result for a different certificate", func(t *testing.T) {
		req := proofTokenRequest(multiAudienceToken, derCertGenerated)

		_, _, err := middleware.AuthenticateWithProofOfPossession(req)

		assert.ErrorContains(t, err, "failed to fetch jwks from remote")
		assert.Equal(t, 2, mockServer.JWKsHitCounter)
	})

	t.Run("does not require a certificate for a single-audience token", func(t *testing.T) {
		mockServer.ProofTokenCertificate = ""
		singleAudienceToken := signProofToken(t, mockServer, mockServer.Config.ClientID)
		req := proofTokenRequest(singleAudienceToken, "")

		token, cert, err := middleware.AuthenticateWithProofOfPossession(req)

		require.NoError(t, err)
		assert.Nil(t, cert)
		assert.Nil(t, token.ServicePlans())
		assert.Empty(t, mockServer.LastJWKsRequestHeader.Get("x-client_cert"))
		assert.Equal(t, "consumer-app-tid", mockServer.LastJWKsRequestHeader.Get("x-azp_app_tid"))
	})
}

func signProofToken(t *testing.T, mockServer *mocks.MockServer, audiences ...string) string {
	t.Helper()
	claims := mocks.NewOIDCClaimsBuilder(mockServer.DefaultClaims()).Audience(audiences...).Build()
	token, err := mockServer.SignTokenWithAdditionalClaims(claims, map[string]interface{}{
		claimAzp:       "consumer-client",
		claimAzpAppTID: "consumer-app-tid",
	}, mockServer.DefaultHeaders())
	require.NoError(t, err)
	return token
}

func proofTokenRequest(token, certificate string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", http.NoBody)
	req.Header.Set(authorization, "Bearer "+token)
	if certificate != "" {
		req.Header.Set("x-forwarded-client-cert", certificate)
	}
	return req
}
