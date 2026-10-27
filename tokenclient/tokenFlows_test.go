// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/httpclient"
	"github.com/sap/cloud-security-client-go/mocks"
	"github.com/sap/cloud-security-client-go/oidcclient"
	"github.com/stretchr/testify/assert"
)

var tokenRequestHandlerHitCounter int
var dummyToken = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo"
var testClientID = "09932670-9440-445d-be3e-432a97d7e2ef"

var mTLSConfig = &env.DefaultIdentity{
	Certificate: "theCertificate",
	Key:         "theCertificateKey",
}

// identityFor returns an identity whose trusted domain matches the test server, so the token
// endpoint can be discovered from it.
func identityFor(t *testing.T, server *httptest.Server, clientID, clientSecret string) *env.DefaultIdentity {
	t.Helper()
	u, err := url.Parse(server.URL)
	assert.NoError(t, err)
	return &env.DefaultIdentity{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Domains:      []string{u.Host},
	}
}

func TestNewTokenFlows_setupDefaultHttpsClientFails(t *testing.T) {
	tokenFlows, err := NewTokenFlows(mTLSConfig, Options{})
	assert.Nil(t, tokenFlows)
	assertError(t, "error creating x509 key pair for DefaultTLSConfig", err)
}

func TestClientCredentialsTokenFlow_FailsWithTimeout(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	timeout, cancelFunc := context.WithTimeout(context.Background(), 0*time.Second)
	defer cancelFunc()
	_, err := tokenFlows.ClientCredentials(timeout, server.URL, RequestOptions{})
	assertError(t, context.DeadlineExceeded.Error(), err)
}

func TestClientCredentialsTokenFlow_FailsNoData(t *testing.T) {
	server := setupNewTLSServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("no json")) })
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing response from https://127.0.0.1", err)
}

func TestClientCredentialsTokenFlow_FailsNoJson(t *testing.T) {
	server := setupNewTLSServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing response from https://127.0.0.1", err)
}

func TestClientCredentialsTokenFlow_FailsUnexpectedJson(t *testing.T) {
	server := setupNewTLSServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{\"a\":\"b\"}")) })
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing requested client credentials token: no 'access_token' property provided", err)
}

func TestClientCredentialsTokenFlow_FailsWithUnauthenticated(t *testing.T) {
	server := setupNewTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthenticated client")) //nolint:errcheck
		tokenRequestHandlerHitCounter++
	})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "failed with status code '401' and payload: 'unauthenticated client'", err)
	var requestFailed *RequestFailedError
	if !errors.As(err, &requestFailed) || requestFailed.StatusCode != 401 {
		assert.Fail(t, "error not of type ClientError")
	}
	assert.Equal(t, 1, tokenRequestHandlerHitCounter)
	assert.Equal(t, 0, tokenFlows.cache.ItemCount())

	_, _ = tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assert.Equal(t, 2, tokenRequestHandlerHitCounter)
}

func TestClientCredentialsTokenFlow_FailsWithCustomerUrlWithoutScheme(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "some-domain.de/with/a/path", RequestOptions{})
	assertError(t, "customer tenant url 'some-domain.de/with/a/path' is not a valid url", err)
	assertError(t, "scheme must be https", err)
}

func TestClientCredentialsTokenFlow_FailsWithInvalidCustomerUrl(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "https://some-domain.de\abc", RequestOptions{})
	assertError(t, "customer tenant url 'https://some-domain.de\abc' can't be parsed", err)
	assertError(t, "parse \"https://some-domain.de\\abc\"", err)
}

func TestClientCredentialsTokenFlow_FailsWithUntrustedCustomerUrl(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "https://attacker.accounts400.ondemand.com", RequestOptions{})
	assertError(t, "does not match any of the trusted domains", err)
}

func TestClientCredentialsTokenFlow_Succeeds(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	token, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertToken(t, dummyToken, token, err)
}

func TestClientCredentialsTokenFlow_ReadFromCache(t *testing.T) {
	server := setupNewTLSServer(t, tokenHandler)
	tokenFlows, _ := NewTokenFlows(identityFor(t, server, testClientID, ""), Options{HTTPClient: server.Client()})

	assert.Equal(t, 0, tokenRequestHandlerHitCounter)
	assert.Equal(t, 0, tokenFlows.cache.ItemCount())

	token, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assert.Equal(t, 1, tokenRequestHandlerHitCounter)
	assert.Equal(t, 1, tokenFlows.cache.ItemCount())
	assertToken(t, dummyToken, token, err)

	token, err = tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assert.Equal(t, 1, tokenRequestHandlerHitCounter)
	assert.Equal(t, 1, tokenFlows.cache.ItemCount())
	assertToken(t, dummyToken, token, err)
	cachedToken, ok := tokenFlows.cache.Get(server.URL + "/oauth2/token?client_id=" + testClientID + "&grant_type=client_credentials")
	assert.True(t, ok)
	assert.Equal(t, dummyToken, cachedToken)
}

func TestClientCredentialsTokenFlow_UsingMockServer_Succeeds(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	assert.NoError(t, err)
	tokenFlows, _ := NewTokenFlows(&env.DefaultIdentity{
		ClientID: mockServer.Config.ClientID,
		Domains:  mockServer.Config.Domains}, Options{HTTPClient: mockServer.Server.Client()})

	token, err := tokenFlows.ClientCredentials(context.TODO(), mockServer.Server.URL, RequestOptions{})
	assertToken(t, "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo", token, err)
}

func setupNewTLSServer(t *testing.T, f func(http.ResponseWriter, *http.Request)) *httptest.Server {
	r := mux.NewRouter()
	r.Use(verifyUserAgent)
	r.HandleFunc("/.well-known/openid-configuration", wellKnownHandler).Methods(http.MethodGet)
	r.HandleFunc("/oauth2/token", f).Methods(http.MethodPost).Headers("Content-Type", "application/x-www-form-urlencoded")

	t.Cleanup(func() {
		tokenRequestHandlerHitCounter = 0
	})
	return httptest.NewTLSServer(r)
}

func verifyUserAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != httpclient.UserAgent {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("wrong user agent, expected: " + httpclient.UserAgent))
		}
		next.ServeHTTP(w, r)
	})
}

// wellKnownHandler serves the OIDC discovery document and advertises the server's own token endpoint.
func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	base := "https://" + r.Host
	payload, _ := json.Marshal(oidcclient.ProviderJSON{
		Issuer:   base,
		JWKsURL:  fmt.Sprintf("%s/oauth2/certs", base),
		TokenURL: fmt.Sprintf("%s/oauth2/token", base),
	})
	_, _ = w.Write(payload)
}

// tokenHandler is the http handler which serves the /oauth2/token endpoint.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r.Body)
	newStr := buf.String()
	if newStr == "client_id="+testClientID+"&grant_type=client_credentials" {
		payload, _ := json.Marshal(tokenResponse{
			Token: dummyToken,
		})
		_, _ = w.Write(payload)
	}
	tokenRequestHandlerHitCounter++
}

func assertToken(t assert.TestingT, expectedToken, actualToken string, actualError error) {
	assert.NoError(t, actualError)
	assert.NotEmpty(t, actualToken)
	assert.Equal(t, expectedToken, actualToken)
}

func assertError(t assert.TestingT, expectedErrorMsg string, actualError error) {
	assert.Error(t, actualError)
	assert.Contains(t, actualError.Error(), expectedErrorMsg)
}
