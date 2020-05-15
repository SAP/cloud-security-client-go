package core

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
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
			name:    "Positive",
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
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
					body, _ := ioutil.ReadAll(response.Body)
					t.Log(string(body))
					t.Errorf("req to test server failed: expected: 200, got: %d", response.StatusCode)
				} else {
					body, _ := ioutil.ReadAll(response.Body)
					t.Log(string(body))
				}
			} else {
				if response.StatusCode != 401 {
					t.Errorf("req to test server succeeded unexpectatly: expected: 401, got: %d", response.StatusCode)
				}
			}
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
