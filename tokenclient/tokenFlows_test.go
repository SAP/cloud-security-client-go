// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/sap/cloud-security-client-go/auth"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

//go:embed testdata/certificate.pem
var certificate string

//go:embed testdata/privateKey.pem
var key string

//go:embed testdata/privateRSAKey.pem
var otherKey string

var mTLSConfig = &env.Identity{
	ClientID:    "09932670-9440-445d-be3e-432a97d7e2ef",
	Certificate: certificate,
	Key:         key,
	URL:         "https://aoxk2addh.accounts400.ondemand.com", // TODO fake it
}

var clientSecretConfig = &env.Identity{
	ClientID:     "09932670-9440-445d-be3e-432a97d7e2ef",
	ClientSecret: "[the_CLIENT.secret:3[/abc",
	URL:          "https://mySaaS.accounts400.ondemand.com",
}

func TestNewTokenFlows_setupDefaultHttpClient(t *testing.T) {
	tokenFlows, err := NewTokenFlows(clientSecretConfig, Options{})
	assert.Nil(t, err)
	assert.NotNil(t, tokenFlows)
	assert.NotNil(t, tokenFlows.options.HTTPClient)
	assert.Nil(t, tokenFlows.options.TLSConfig)
}

func TestNewTokenFlows_setupDefaultHttpsClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip test on windows os. Module crypto/x509 supports SystemCertPool with go 1.18 (https://go-review.googlesource.com/c/go/+/353589/)")
	}
	tokenFlows, err := NewTokenFlows(mTLSConfig, Options{})
	assert.Nil(t, err)
	assert.NotNil(t, tokenFlows)
	assert.NotNil(t, tokenFlows.options.HTTPClient)
	assert.NotNil(t, tokenFlows.options.TLSConfig)
}

func TestDefaultTLSConfig_shouldFailIfKeyDoesNotMatch(t *testing.T) {
	mTLSConfig.Certificate = otherKey
	tLSConfig, err := defaultTLSConfig(mTLSConfig)
	assert.Nil(t, tLSConfig)
	assert.Error(t, err)
}

func TestClientCredentialsTokenFlow_FailsWithTimeout(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	timeout, cancelFunc := context.WithTimeout(context.Background(), 0*time.Second)
	defer cancelFunc()
	_, err := tokenFlows.ClientCredentials("", RequestOptions{Context: timeout})
	assertClientError(t, context.DeadlineExceeded.Error(), err)
}

func TestClientCredentialsTokenFlow_FailsNoData(t *testing.T) {
	server := setupNewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("", RequestOptions{})
	assertClientError(t, "provides no valid json content", err)
}

func TestClientCredentialsTokenFlow_FailsUnexpectedJson(t *testing.T) {
	server := setupNewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{\"a\":\"b\"}")) })) //nolint:errcheck
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("", RequestOptions{})
	assertClientError(t, "error parsing requested client credential token", err)
}

func TestClientCredentialsTokenFlow_FailsUnexpectedToken(t *testing.T) {
	server := setupNewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{\"access_token\":\"abc\"}")) })) //nolint:errcheck
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("", RequestOptions{})
	assertClientError(t, "error parsing requested client credential token", err)
}

func TestClientCredentialsTokenFlow_FailsWithUnauthenticated(t *testing.T) {
	server := setupNewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("", RequestOptions{})
	assertClientError(t, "failed with status code 401 Unauthorized", err)
}

func TestClientCredentialsTokenFlow_FailsWithInvalidCustomHost(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("invalidhost", RequestOptions{})
	assertClientError(t, "customer tenant host 'invalidhost' can't be accepted", err)
}

func TestClientCredentialsTokenFlow_FailsWithInvalidUrls(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	clientSecretConfig.URL = "invalidhost"
	tokenFlows, _ := NewTokenFlows(clientSecretConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials("", RequestOptions{})
	assertClientError(t, "unsupported protocol scheme", err)
}

func TestClientCredentialsTokenFlow_Succeeds(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(&env.Identity{URL: server.URL}, Options{HTTPClient: server.Client()})

	token, err := tokenFlows.ClientCredentials("", RequestOptions{Params: map[string]string{
		"client_id": "09932670-9440-445d-be3e-432a97d7e2ef",
	}})
	assertToken(t, "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo", token, err)
}

func TestClientCredentialsTokenFlow_SucceedsWithCustomHost(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	token, err := tokenFlows.ClientCredentials(server.URL, RequestOptions{})
	assertToken(t, "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo", token, err)
}

func setupNewTLSServer(f func(http.ResponseWriter,
	*http.Request)) *httptest.Server {
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
			Token: "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo",
		})
		_, _ = w.Write(payload)
	}
}

func assertToken(t assert.TestingT, expectedToken string, actualToken auth.Token, actualError *ClientError) {
	assert.Nil(t, actualError)
	assert.NotNil(t, actualToken)
	assert.Equal(t, expectedToken, actualToken.TokenValue())
}

func assertClientError(t assert.TestingT, expectedErrorMsg string, actualError *ClientError) {
	assert.Contains(t, actualError.Error(), expectedErrorMsg)
	assert.IsType(t, actualError, (*ClientError)(nil))
}
