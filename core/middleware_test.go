package core

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnd2End(t *testing.T) {
	testServer, oidcMockServer := GetTestServer()
	defer testServer.Close()
	defer oidcMockServer.Server.Close()
	client := testServer.Client()

	tests := []struct {
		name    string
		claims  OIDCClaims
		wantErr bool
	}{
		{
			name:    "valid",
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
		}, {
			name: "expired",
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ExpiresAt(time.Now().Add(-5 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name: "before validity",
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				NotBefore(time.Now().Add(5 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name: "wrong audience",
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient").
				Build(),
			wantErr: true,
		}, {
			name: "wrong issuer",
			claims: NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("https://another.oidc-server.com/").
				Build(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/helloWorld", nil)
			authHeader, _ := oidcMockServer.SignToken(tt.claims)
			req.Header.Add("Authorization", "Bearer "+authHeader)
			response, err := client.Do(req)
			if err != nil {
				t.Errorf("unexpected error during request: %v", err)
			}

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
