package core

import (
	"fmt"
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
	req, _ := http.NewRequest("GET", testServer.URL+"/helloWorld", nil)
	authHeader, _ := oidcMockServer.SignToken(oidcMockServer.DefaultClaims())
	req.Header.Add("Authorization", "Bearer "+authHeader)
	response, err := client.Do(req)
	if err != nil {
		t.Errorf("unexpected error during request: %v", err)
	}
	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		fmt.Println(string(body))
		t.Errorf("req to test server failed: expected: 200, got: %d", response.StatusCode)
	}
}

func GetTestHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		//panic("test entered test handler, this should not happen")
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

func GetTestOptions() Options {
	mockServer := NewOIDCMockServer()
	return Options{
		UserContext: "custom",
		OAuthConfig: mockServer.Config,
		HTTPClient:  mockServer.Server.Client(),
	}
}
