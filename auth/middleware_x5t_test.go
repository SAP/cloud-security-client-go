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

func TestAuthenticateWithProofOfPossession_X5TValidation(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	require.NoError(t, err)
	defer mockServer.Server.Close()

	middleware := NewMiddleware(mockServer.Config, Options{
		HTTPClient: mockServer.Server.Client(),
		Validation: ValidationOptions{X5T: true},
	})
	matchingToken, err := mockServer.SignTokenWithAdditionalClaims(
		mockServer.DefaultClaims(),
		map[string]interface{}{claimCnf: map[string]interface{}{claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM"}},
		mockServer.DefaultHeaders(),
	)
	require.NoError(t, err)
	missingConfirmationToken, err := mockServer.SignToken(mockServer.DefaultClaims(), mockServer.DefaultHeaders())
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		certificate string
		wantErr     string
	}{
		{
			name:        "accepts matching certificate",
			token:       matchingToken,
			certificate: derCertFromFile,
		},
		{
			name:    "rejects missing certificate",
			token:   matchingToken,
			wantErr: ErrNoClientCert.Error(),
		},
		{
			name:        "rejects non-matching certificate",
			token:       matchingToken,
			certificate: derCertGenerated,
			wantErr:     "token thumbprint confirmation failed",
		},
		{
			name:        "rejects token without x5t confirmation",
			token:       missingConfirmationToken,
			certificate: derCertFromFile,
			wantErr:     "token provides no cnf member for thumbprint confirmation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", http.NoBody)
			req.Header.Set(authorization, "Bearer "+tt.token)
			req.Header.Set("x-forwarded-client-cert", tt.certificate)

			_, cert, err := middleware.AuthenticateWithProofOfPossession(req)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, cert)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)
			assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
		})
	}
}

func TestAuthenticationHandler_X5TValidationOnlyExposesValidatedCertificate(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	require.NoError(t, err)
	defer mockServer.Server.Close()

	middleware := NewMiddleware(mockServer.Config, Options{
		HTTPClient: mockServer.Server.Client(),
		Validation: ValidationOptions{X5T: true},
	})
	token, err := mockServer.SignTokenWithAdditionalClaims(
		mockServer.DefaultClaims(),
		map[string]interface{}{claimCnf: map[string]interface{}{claimCnfMemberX5t: "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM"}},
		mockServer.DefaultHeaders(),
	)
	require.NoError(t, err)

	handlerCalled := false
	handler := middleware.AuthenticationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		cert, ok := ClientCertificateFromCtx(r)
		require.True(t, ok)
		require.NotNil(t, cert)
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("does not invoke downstream handler for a non-matching certificate", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", http.NoBody)
		req.Header.Set(authorization, "Bearer "+token)
		req.Header.Set("x-forwarded-client-cert", derCertGenerated)
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		assert.Equal(t, http.StatusUnauthorized, res.Code)
		assert.False(t, handlerCalled)
	})

	t.Run("invokes downstream handler with a matching certificate", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", http.NoBody)
		req.Header.Set(authorization, "Bearer "+token)
		req.Header.Set("x-forwarded-client-cert", derCertFromFile)
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code)
		assert.True(t, handlerCalled)
	})
}
