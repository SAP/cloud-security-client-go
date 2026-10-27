// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryClientKeepsTLSConfigurationSeparate(t *testing.T) {
	sessionCache := tls.NewLRUClientSessionCache(1)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{}},
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
		ClientSessionCache: sessionCache,
	}}
	client := &http.Client{Transport: transport}
	discovery, closeIdleConnections := discoveryClient(client)
	t.Cleanup(closeIdleConnections)
	discoveryTransport, ok := discovery.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotSame(t, transport, discoveryTransport)
	assert.NotSame(t, transport.TLSClientConfig, discoveryTransport.TLSClientConfig)
	assert.Equal(t, transport.TLSClientConfig.MinVersion, discoveryTransport.TLSClientConfig.MinVersion)
	assert.Empty(t, discoveryTransport.TLSClientConfig.Certificates)
	assert.Nil(t, discoveryTransport.TLSClientConfig.GetClientCertificate)
	assert.Nil(t, discoveryTransport.TLSClientConfig.ClientSessionCache)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.NotNil(t, transport.TLSClientConfig.GetClientCertificate)
	assert.Same(t, sessionCache, transport.TLSClientConfig.ClientSessionCache)
}

func TestOIDCTenantRejectsJWKSRedirect(t *testing.T) {
	var sinkRequests atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		sinkRequests.Add(1)
	}))
	t.Cleanup(sink.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			assert.NoError(t, json.NewEncoder(w).Encode(ProviderJSON{
				Issuer: "https://" + r.Host, JWKsURL: "https://" + r.Host + "/keys",
			}))
			return
		}
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	tenant, err := NewOIDCTenant(server.Client(), u.Host)
	require.NoError(t, err)
	_, err = tenant.GetJWKs(ClientInfo{})
	assert.Error(t, err)
	assert.Zero(t, sinkRequests.Load())
}
