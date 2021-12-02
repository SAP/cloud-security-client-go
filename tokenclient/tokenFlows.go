// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/sap/cloud-security-client-go/auth"
	"github.com/sap/cloud-security-client-go/env"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options allows configuration http(s) client
type Options struct {
	HTTPClient *http.Client // Default: basic http.Client with a timeout of 10 seconds and allowing 50 idle connections. It uses given TLSConfig.
	TLSConfig  *tls.Config  // In case of cert-based identity config. Default: SystemCertPool with cert/key from identity config.
}

// RequestOptions allows to configure the token request
type RequestOptions struct {
	// Request parameters that shall be overwritten or added to the payload
	Params map[string]string
}

// TokenFlows setup once per application.
type TokenFlows struct {
	identity *env.Identity
	options  Options
	tokenURI string
}

type tokenResponse struct {
	Token string `json:"access_token"`
}

const (
	tokenEndpoint              string = "/oauth2/token" //nolint:gosec
	grantTypeParameter         string = "grant_type"
	grantTypeClientCredentials string = "client_credentials"
	clientIDParameter          string = "client_id"
	clientSecretParameter      string = "client_secret"
)

// NewTokenFlows initializes token flows
//
// identity provides credentials and url to authenticate client with identity service
// options specifies rest client and its tls config, both can be overwritten.
// Note: Setup of default tls config is not supported for windows os. Module crypto/x509 supports SystemCertPool with go 1.18 (https://go-review.googlesource.com/c/go/+/353589/)
func NewTokenFlows(identity *env.Identity, options Options) (*TokenFlows, error) {
	t := new(TokenFlows)
	t.identity = identity
	if options.HTTPClient == nil {
		if options.TLSConfig == nil && identity.IsCertificateBased() {
			defaultConfig, err := defaultTLSConfig(identity)
			if err != nil {
				return nil, err
			}
			options.TLSConfig = defaultConfig
		}
		options.HTTPClient = defaultHTTPClient(options.TLSConfig)
	}
	t.options = options
	t.tokenURI = identity.GetURL() + tokenEndpoint
	return t, nil
}

// ClientCredentials implements the client credentials flow (RFC 6749, section 4.4).
// Clients obtain an access token outside of the context of a user.
// It is used for non interactive applications (a CLI, a batch job, or for service-2-service communication) where the token is issued to the application itself,
// instead of an end user for accessing resources without principal propagation.
//
// ctx carries the request context like the deadline or other values that should be shared across API boundaries. Default: context.TODO is used
// customerTenantURL like "https://custom.accounts400.ondemand.com" gives the host of the customers ias tenant
// options allows to provide a request context and optionally additional request parameters
func (t *TokenFlows) ClientCredentials(ctx context.Context, customerTenantURL string, options RequestOptions) (auth.Token, error) {
	data := url.Values{}
	data.Set(grantTypeParameter, grantTypeClientCredentials)
	data.Set(clientIDParameter, t.identity.GetClientID())
	if t.identity.GetClientSecret() != "" {
		data.Set(clientSecretParameter, t.identity.GetClientSecret())
	}
	for name, value := range options.Params {
		data.Set(name, value) // potentially overwrites data which was set before
	}
	targetURL, err := t.getURL(customerTenantURL)
	if err != nil {
		return nil, err
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(data.Encode())) // URL-encoded payload
	if e != nil {
		return nil, fmt.Errorf("error performing client credentials flow: %w", e)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenJSON, err := t.performRequest(r)
	if err != nil {
		return nil, err
	}
	var response tokenResponse
	_ = json.Unmarshal(tokenJSON, &response)
	token, e := auth.NewToken(response.Token)
	if e != nil {
		return nil, fmt.Errorf("error parsing requested client credential token: %w", e)
	}
	return token, nil
}

func (t *TokenFlows) getURL(customerTenantHost string) (string, error) {
	if customerTenantHost == "" {
		return t.tokenURI, nil
	}
	customHost, err := url.Parse(customerTenantHost)
	if err == nil && customHost.Host != "" {
		return "https://" + customHost.Host + tokenEndpoint, nil
	}
	return "", fmt.Errorf("customer tenant host '%v' can't be accepted: %v", customerTenantHost, err)
}

func (t *TokenFlows) performRequest(r *http.Request) ([]byte, error) {
	res, err := t.options.HTTPClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("request to '%v' failed: %w", r.URL, err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to '%v' failed with status code '%v' and payload: '%v'", r.URL, res.StatusCode, string(body))
	}
	if err != nil || body == nil || !json.Valid(body) {
		return nil, fmt.Errorf("request to '%v ' provides no valid json content: %w", r.URL, err)
	}
	return body, nil
}

func defaultTLSConfig(identity *env.Identity) (*tls.Config, error) {
	certPEMBlock := []byte(identity.GetCertificate())
	keyPEMBlock := []byte(identity.GetKey())

	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 key pair for defaultTLSConfig: %w", err)
	}
	tlsCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error setting up cert pool for defaultTLSConfig: %w", err)
	}
	ok := tlsCertPool.AppendCertsFromPEM(certPEMBlock)
	if !ok {
		return nil, fmt.Errorf("error adding certs to pool for defaultTLSConfig: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      tlsCertPool,
		Certificates: []tls.Certificate{tlsCert},
	}
	return tlsConfig, nil
}

// TODO avoid duplication
func defaultHTTPClient(tlsConfig *tls.Config) *http.Client {
	client := &http.Client{
		Timeout: time.Second * 10, // TODO check
	}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConnsPerHost: 50, // TODO check
		}
	}
	return client
}
