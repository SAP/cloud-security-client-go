// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var tokenRequestHandlerHitCounter int
var dummyToken = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo" //nolint:gosec

var clientSecretConfig = &env.DefaultIdentity{
	ClientID:     "09932670-9440-445d-be3e-432a97d7e2ef",
	ClientSecret: "[the_CLIENT.secret:3[/abc",
}

var mTLSConfig = &env.DefaultIdentity{
	Certificate: "theCertificate",
	Key:         "theCertificateKey",
}

func TestNewTokenFlows_setupDefaultHttpsClientFails(t *testing.T) {
	tokenFlows, err := NewTokenFlows(mTLSConfig, Options{})
	assert.Nil(t, tokenFlows)
	assertError(t, "error creating x509 key pair for DefaultTLSConfig", err)
}

func TestClientCredentialsTokenFlow_FailsWithTimeout(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	timeout, cancelFunc := context.WithTimeout(context.Background(), 0*time.Second)
	defer cancelFunc()
	_, err := tokenFlows.ClientCredentials(timeout, server.URL, RequestOptions{})
	assertError(t, context.DeadlineExceeded.Error(), err)
}

func TestClientCredentialsTokenFlow_FailsNoData(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("no json")) })
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing response from https://127.0.0.1", err)
}

func TestClientCredentialsTokenFlow_FailsNoJson(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing response from https://127.0.0.1", err)
}

func TestClientCredentialsTokenFlow_FailsUnexpectedJson(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{\"a\":\"b\"}")) })
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing requested client credentials token: no 'access_token' property provided", err)
}

func TestClientCredentialsTokenFlow_FailsWithUnauthenticated(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthenticated client")) //nolint:errcheck
		tokenRequestHandlerHitCounter++
	})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

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
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(clientSecretConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "some-domain.de/with/a/path", RequestOptions{})
	assertError(t, "customer tenant url 'some-domain.de/with/a/path' is not a valid url", err)
	assertError(t, "Trying to parse a hostname without a scheme is invalid", err)
}

func TestClientCredentialsTokenFlow_FailsWithInvalidCustomerUrl(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(clientSecretConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "https://some-domain.de\abc", RequestOptions{})
	assertError(t, "customer tenant url 'https://some-domain.de\abc' can't be parsed", err)
	assertError(t, "parse \"https://some-domain.de\\abc\"", err)
}

func TestClientCredentialsTokenFlow_Succeeds(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	tokenFlows, _ := NewTokenFlows(&env.DefaultIdentity{
		ClientID: "09932670-9440-445d-be3e-432a97d7e2ef"}, Options{HTTPClient: server.Client()})

	token, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertToken(t, dummyToken, token, err)
}

<<<<<<< HEAD
=======
func TestClientCredentialsTokenFlow_UsingMockServer_Succeeds(t *testing.T) {
	mockServer, err := mocks.NewOIDCMockServer()
	assert.NoError(t, err)
	tokenFlows, _ := NewTokenFlows(&env.DefaultIdentity{
		ClientID: mockServer.Config.ClientID}, Options{HTTPClient: mockServer.Server.Client()})

	token, err := tokenFlows.ClientCredentials(context.TODO(), mockServer.Server.URL, RequestOptions{})
	assertToken(t, dummyToken, token, err)
}

func TestClientCredentialsTokenFlow_ReadFromCache(t *testing.T) {
	tokenRequestHandlerHitCounter = 0
	server := setupNewTLSServer(tokenHandler)
	tokenFlows, _ := NewTokenFlows(&env.DefaultIdentity{
		ClientID: "09932670-9440-445d-be3e-432a97d7e2ef"}, Options{HTTPClient: server.Client()})

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
	cachedToken, ok := tokenFlows.cache.Get(server.URL + "/oauth2/token?client_id=09932670-9440-445d-be3e-432a97d7e2ef&grant_type=client_credentials")
	assert.True(t, ok)
	assert.Equal(t, dummyToken, cachedToken)
}

>>>>>>> 3b06e3e (introduce cache for token requests)
func setupNewTLSServer(f func(http.ResponseWriter, *http.Request)) *httptest.Server {
	r := mux.NewRouter()
	r.HandleFunc("/oauth2/token", f).Methods(http.MethodPost).Headers("Content-Type", "application/x-www-form-urlencoded")
	return httptest.NewTLSServer(r)
}

// tokenHandler is the http handler which serves the /oauth2/token endpoint.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r.Body)
	newStr := buf.String()
	if newStr == "client_id=09932670-9440-445d-be3e-432a97d7e2ef&grant_type=client_credentials" {
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
