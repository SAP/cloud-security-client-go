// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnd2End(t *testing.T) {
	testServer, oidcMockServer := GetTestServer()
	client := testServer.Client()
	defer testServer.Close()
	defer oidcMockServer.Server.Close()

	tests := []struct {
		name    string
		header  map[string]interface{}
		claims  OIDCClaims
		wantErr bool
	}{
		{
			name:    "valid",
			header:  oidcMockServer.DefaultHeaders(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
		}, {
			name:   "valid with aud array",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient", oidcMockServer.Config.ClientID).
				Build(),
			wantErr: false,
		}, {
			name: "no key id in token",
			header: NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				KeyID("").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
		}, {
			name:   "expired",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ExpiresAt(time.Now().Add(-5 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name:   "before validity",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				NotBefore(time.Now().Add(5 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name:   "wrong audience",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient").
				Build(),
			wantErr: true,
		}, {
			name:   "wrong audience array",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient", "neitherThisOne").
				Build(),
			wantErr: true,
		}, {
			name:   "wrong issuer",
			header: oidcMockServer.DefaultHeaders(),
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("https://another.oidc-server.com/").
				Build(),
			wantErr: true,
		}, {
			name: "wrong key id",
			header: NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				KeyID("wrongKey").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name: "none algorithm",
			header: NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				Alg("none").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name: "wrong algorithm",
			header: NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				Alg("HS256").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/helloWorld", nil)
			authHeader, _ := oidcMockServer.SignToken(tt.claims, tt.header)
			req.Header.Add("Authorization", "Bearer "+authHeader)
			response, err := client.Do(req)
			if err != nil {
				t.Errorf("unexpected error during request: %v", err)
			}
			defer response.Body.Close()

			if tt.wantErr == false {
				if response.StatusCode != 200 {
					t.Errorf("req to test server failed: expected: 200, got: %d", response.StatusCode)
				}
			} else {
				if response.StatusCode != 401 {
					t.Errorf("req to test server succeeded unexpectatly: expected: 401, got: %d", response.StatusCode)
				}
			}
			body, _ := ioutil.ReadAll(response.Body)
			t.Log(string(body))
		})
	}
}

func GetTestHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		_, _ = rw.Write([]byte("entered test handler"))
	}
}

func GetTestServer() (clientServer *httptest.Server, oidcServer *MockServer) {
	mockServer := NewOIDCMockServer()
	options := Options{
		UserContext:  "myprop",
		OAuthConfig:  mockServer.Config,
		ErrorHandler: nil,
		HTTPClient:   mockServer.Server.Client(),
	}
	middleware := NewAuthMiddleware(options)
	server := httptest.NewTLSServer(middleware.Handler(GetTestHandler()))

	return server, mockServer
}
