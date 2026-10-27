// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/oidcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestClientCredentialsPreservesEndpointPaths(t *testing.T) {
	for _, endpoint := range []string{"", "/oauth/token", "/nested/token%2Fexchange"} {
		t.Run("path="+endpoint, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				expectedPath := endpoint
				if expectedPath == "" {
					expectedPath = "/oauth2/token"
				}
				assert.Equal(t, expectedPath, r.URL.EscapedPath())
				assert.Equal(t, http.MethodPost, r.Method)
				assert.NoError(t, r.ParseForm())
				assert.Equal(t, "test-secret", r.PostForm.Get("client_secret"))
				assert.Equal(t, "test-scope", r.PostForm.Get("scope"))
				assert.NoError(t, json.NewEncoder(w).Encode(tokenResponse{Token: dummyToken}))
			}))
			t.Cleanup(server.Close)
			identity := identityFor(t, server, testClientID)
			identity.ClientSecret = "test-secret"
			flows, err := NewTokenFlows(identity, Options{HTTPClient: server.Client()})
			require.NoError(t, err)

			options := RequestOptions{Params: map[string]string{"scope": "test-scope"}, TokenEndpoint: endpoint}
			token, err := flows.ClientCredentials(context.Background(), server.URL, options)
			assertToken(t, dummyToken, token, err)
			assert.EqualValues(t, 1, requests.Load())
		})
	}
}

func TestClientCredentialsRejectsEndpointPathsBeforeRequest(t *testing.T) {
	endpoints := []string{
		"@attacker.example/collect", "/@attacker.example/collect", "/%40attacker.example/collect",
		"https://attacker.example/collect", "//attacker.example/collect", "/%2Fattacker.example/collect",
		"token", "/token?query=value", "/token?", "/token#fragment", "/token#",
		"/\\attacker.example/collect", "/%5Cattacker.example/collect", "/%zz", "/token\n",
	}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			var requests int
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("unexpected request")
			})}
			flows, err := NewTokenFlows(&env.DefaultIdentity{Domains: []string{"accounts.example.com"}}, Options{HTTPClient: client})
			require.NoError(t, err)
			token, err := flows.ClientCredentials(context.Background(), "https://tenant.accounts.example.com", RequestOptions{TokenEndpoint: endpoint})
			assert.Error(t, err)
			assert.Empty(t, token)
			assert.Zero(t, requests)
		})
	}
}

func TestClientCredentialsRejectsTenantBeforeRequest(t *testing.T) {
	urls := []string{
		"tenant.accounts.example.com", "//tenant.accounts.example.com", "http://tenant.accounts.example.com",
		"https://user@tenant.accounts.example.com", "https://tenant.accounts.example.com@attacker.example",
		"https://attacker.example", "https://evilaccounts.example.com", "https://deep.tenant.accounts.example.com",
		"https://tenant.accounts.example.com:443", "https://tenant.accounts.example.com:8443",
		"https://tenant.accounts.example.com:", "https://tenant.accounts.example.com.",
		"https://tenant.accounts.example.com/path", "https://tenant.accounts.example.com/%2f",
		"https://tenant.accounts.example.com?", "https://tenant.accounts.example.com?query=value",
		"https://tenant.accounts.example.com#", "https://tenant.accounts.example.com#fragment",
		"https:///token", "https:tenant.accounts.example.com", "https://tenant.accounts.example.com\n",
	}
	for _, tenantURL := range urls {
		t.Run(tenantURL, func(t *testing.T) {
			var requests int
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("unexpected request")
			})}
			flows, err := NewTokenFlows(&env.DefaultIdentity{Domains: []string{"accounts.example.com"}}, Options{HTTPClient: client})
			require.NoError(t, err)
			_, err = flows.ClientCredentials(context.Background(), tenantURL, RequestOptions{})
			assert.Error(t, err)
			_, err = flows.ClientCredentialsWithDiscovery(context.Background(), tenantURL, nil)
			assert.Error(t, err)
			assert.Zero(t, requests)
		})
	}
}

func TestClientCredentialsWithDiscoveryUsesEndpointAndCaches(t *testing.T) {
	var discoveryRequests, tokenRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryRequests.Add(1)
			writeDiscovery(t, w, "https://"+r.Host, "https://"+r.Host+"/configured/token?audience=example")
			return
		}
		tokenRequests.Add(1)
		assert.Equal(t, "/configured/token", r.URL.Path)
		assert.Equal(t, "example", r.URL.Query().Get("audience"))
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		assert.Equal(t, testClientID, r.PostForm.Get("client_id"))
		assert.NoError(t, json.NewEncoder(w).Encode(tokenResponse{Token: dummyToken}))
	}))
	t.Cleanup(server.Close)
	flows, err := NewTokenFlows(identityFor(t, server, testClientID), Options{HTTPClient: server.Client()})
	require.NoError(t, err)
	for _, scope := range []string{"first", "second", "second"} {
		token, tokenErr := flows.ClientCredentialsWithDiscovery(context.Background(), server.URL, map[string]string{"scope": scope})
		assertToken(t, dummyToken, token, tokenErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = flows.ClientCredentialsWithDiscovery(ctx, server.URL, nil)
	assert.ErrorIs(t, err, context.Canceled)
	assert.EqualValues(t, 1, discoveryRequests.Load())
	assert.EqualValues(t, 2, tokenRequests.Load())
}

func TestClientCredentialsWithDiscoveryValidatesEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		valid    bool
	}{
		{"https://tenant.accounts.example.com/token", true},
		{"https://other.accounts.example.com/token", true},
		{"https://accounts.example.com/token", true},
		{"", false},
		{"/token", false},
		{"http://tenant.accounts.example.com/token", false},
		{"https://attacker.example/token", false},
		{"https://deep.tenant.accounts.example.com/token", false},
		{"https://user:password@tenant.accounts.example.com/token", false},
		{"https://tenant.accounts.example.com:443/token", false},
		{"https://tenant.accounts.example.com:8443/token", false},
		{"https://tenant.accounts.example.com/token#fragment", false},
		{"https://tenant.accounts.example.com/token#", false},
		{"https:tenant.accounts.example.com/token", false},
		{"https:///token", false},
		{"//attacker.example/token", false},
		{"https://tenant.accounts.example.com/%zz", false},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			var requests int
			body, err := json.Marshal(oidcclient.ProviderJSON{
				Issuer: "https://tenant.accounts.example.com", JWKsURL: "https://tenant.accounts.example.com/keys", TokenURL: tt.endpoint,
			})
			require.NoError(t, err)
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				payload := string(body)
				if requests > 1 {
					assert.Equal(t, tt.endpoint, r.URL.String())
					payload = `{"access_token":"` + dummyToken + `"}`
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
			})}
			flows, err := NewTokenFlows(&env.DefaultIdentity{Domains: []string{"accounts.example.com"}}, Options{HTTPClient: client})
			require.NoError(t, err)
			token, err := flows.ClientCredentialsWithDiscovery(context.Background(), "https://tenant.accounts.example.com", nil)
			if tt.valid {
				assertToken(t, dummyToken, token, err)
				assert.Equal(t, 2, requests)
			} else {
				assert.Error(t, err)
				assert.Empty(t, token)
				assert.Equal(t, 1, requests)
				assert.Zero(t, flows.oidcConfig.ItemCount())
			}
		})
	}
}

func TestClientCredentialsRejectsRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, stage := range []string{"legacy-token", "discovery", "discovered-token"} {
			t.Run(fmt.Sprintf("%s/%d", stage, status), func(t *testing.T) {
				var sinkRequests atomic.Int32
				sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					sinkRequests.Add(1)
					assert.NoError(t, json.NewEncoder(w).Encode(tokenResponse{Token: dummyToken}))
				}))
				t.Cleanup(sink.Close)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/.well-known/openid-configuration" && stage != "discovery" {
						writeDiscovery(t, w, "https://"+r.Host, "https://"+r.Host+"/token")
						return
					}
					http.Redirect(w, r, sink.URL+"/collect", status)
				}))
				t.Cleanup(server.Close)
				client := server.Client()
				var redirectCallbacks int
				client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
					redirectCallbacks++
					return nil
				}
				identity := identityFor(t, server, testClientID)
				identity.ClientSecret = "test-secret"
				flows, err := NewTokenFlows(identity, Options{HTTPClient: client})
				require.NoError(t, err)
				var token string
				if stage == "legacy-token" {
					token, err = flows.ClientCredentials(context.Background(), server.URL, RequestOptions{})
				} else {
					token, err = flows.ClientCredentialsWithDiscovery(context.Background(), server.URL, nil)
				}
				assert.Error(t, err)
				assert.Empty(t, token)
				assert.Zero(t, sinkRequests.Load())
				assert.Zero(t, redirectCallbacks)
				require.NotNil(t, client.CheckRedirect)
				assert.NoError(t, client.CheckRedirect(nil, nil))
				assert.Equal(t, 1, redirectCallbacks)
			})
		}
	}
}

func TestClientCredentialsWithDiscoveryOmitsClientCertificate(t *testing.T) {
	var discoveryCertificates, tokenCertificates atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryCertificates.Store(int32(len(r.TLS.PeerCertificates)))
			writeDiscovery(t, w, "https://"+r.Host, "https://"+r.Host+"/token")
			return
		}
		tokenCertificates.Store(int32(len(r.TLS.PeerCertificates)))
		assert.NoError(t, json.NewEncoder(w).Encode(tokenResponse{Token: dummyToken}))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	certificate := server.TLS.Certificates[0]
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	transport.TLSClientConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &certificate, nil
	}
	flows, err := NewTokenFlows(identityFor(t, server, testClientID), Options{HTTPClient: client})
	require.NoError(t, err)
	token, err := flows.ClientCredentialsWithDiscovery(context.Background(), server.URL, nil)
	assertToken(t, dummyToken, token, err)
	assert.Zero(t, discoveryCertificates.Load())
	assert.EqualValues(t, 1, tokenCertificates.Load())
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.NotNil(t, transport.TLSClientConfig.GetClientCertificate)
}

func TestClientCredentialsWithDiscoveryUsesRequestContext(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	flows, err := NewTokenFlows(identityFor(t, server, testClientID), Options{HTTPClient: server.Client()})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, requestErr := flows.ClientCredentialsWithDiscovery(ctx, server.URL, nil)
		result <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery request did not start")
	}
	cancel()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("discovery request ignored cancellation")
	}
}

func writeDiscovery(t *testing.T, w http.ResponseWriter, issuer, endpoint string) {
	t.Helper()
	assert.NoError(t, json.NewEncoder(w).Encode(oidcclient.ProviderJSON{
		Issuer: issuer, JWKsURL: issuer + "/keys", TokenURL: endpoint,
	}))
}
