// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var clientSecretConfig = env.Identity{
	ClientID:     "09932670-9440-445d-be3e-432a97d7e2ef",
	ClientSecret: "[the_CLIENT.secret:3[/abc",
}

var mTLSConfig = env.Identity{
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
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "provides no valid json content", err)
}

func TestClientCredentialsTokenFlow_FailsUnexpectedJson(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{\"a\":\"b\"}")) }) //nolint:errcheck
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "error parsing requested client credential token: {\"a\":\"b\"}", err)
}

func TestClientCredentialsTokenFlow_FailsWithUnauthenticated(t *testing.T) {
	server := setupNewTLSServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthenticated client")) //nolint:errcheck
	})
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(mTLSConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertError(t, "failed with status code '401' and payload: 'unauthenticated client'", err)
}

func TestClientCredentialsTokenFlow_FailsWithInvalidCustomHost(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(clientSecretConfig, Options{HTTPClient: server.Client()})

	_, err := tokenFlows.ClientCredentials(context.TODO(), "invalidhost", RequestOptions{})
	assertError(t, "customer tenant host 'invalidhost' can't be accepted", err)
}

func TestClientCredentialsTokenFlow_Succeeds(t *testing.T) {
	server := setupNewTLSServer(tokenHandler)
	defer server.Close()
	tokenFlows, _ := NewTokenFlows(env.Identity{
		ClientID: "09932670-9440-445d-be3e-432a97d7e2ef"}, Options{HTTPClient: server.Client()})

	token, err := tokenFlows.ClientCredentials(context.TODO(), server.URL, RequestOptions{})
	assertToken(t, "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo", token, err)
}

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
			Token: "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo",
		})
		_, _ = w.Write(payload)
	}
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
