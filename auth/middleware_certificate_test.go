// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sap/cloud-security-client-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateWithProofOfPossession_PreservesOptionalCertificate(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	require.NoError(t, err)
	defer mockServer.Server.Close()

	middleware := NewMiddleware(mockServer.Config, Options{HTTPClient: mockServer.Server.Client()})
	token, err := mockServer.SignToken(mockServer.DefaultClaims(), mockServer.DefaultHeaders())
	require.NoError(t, err)

	t.Run("returns a forwarded certificate without ownership validation", func(t *testing.T) {
		req := certificateRequest(token, derCertFromFile)

		_, cert, err := middleware.AuthenticateWithProofOfPossession(req)

		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
	})

	t.Run("rejects an invalid forwarded certificate", func(t *testing.T) {
		req := certificateRequest(token, "invalid certificate")

		_, _, err := middleware.AuthenticateWithProofOfPossession(req)

		assert.Error(t, err)
	})

	t.Run("adds a forwarded certificate to the request context", func(t *testing.T) {
		handler := middleware.AuthenticationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cert, ok := ClientCertificateFromCtx(r)
			require.True(t, ok)
			require.NotNil(t, cert)
			assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
			w.WriteHeader(http.StatusNoContent)
		}))
		req := certificateRequest(token, derCertFromFile)
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code)
	})
}

func certificateRequest(token, certificate string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", http.NoBody)
	req.Header.Set(authorization, "Bearer "+token)
	req.Header.Set("x-forwarded-client-cert", certificate)
	return req
}
