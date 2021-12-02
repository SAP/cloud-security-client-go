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
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Options struct {
	HTTPClient *http.Client // TODO Default: basic http.Client with a timeout of 15 seconds
	TLSConfig  *tls.Config  // TODO Default:
}

// RequestOptions allows to configure the token request
type RequestOptions struct {
	// Context carries the request context like the deadline or other values that should be shared across API boundaries.
	Context context.Context
	// Request parameters that shall be overwritten or added to the payload
	Params map[string]string
}

type TokenFlows struct {
	identity *env.Identity
	options  Options
	tokenURI string
}

type ClientError struct {
	msg string
	err error
}

func (e *ClientError) Error() string {
	if e.err == nil {
		return e.msg
	}
	return fmt.Sprintf("%s: %s", e.msg, e.err.Error())
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
func NewTokenFlows(identity *env.Identity, options Options) (*TokenFlows, *ClientError) {
	t := TokenFlows{Identity: identity}
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
// options allows to provide a request context and optionally additional request parameters
func (t *TokenFlows) ClientCredentials(customerTenantHost string, options RequestOptions) (auth.Token, *ClientError) {
	data := url.Values{}
	data.Set(grantTypeParameter, grantTypeClientCredentials)
	data.Set(clientIDParameter, t.identity.GetClientID())
	if t.identity.GetClientSecret() != "" {
		data.Set(clientSecretParameter, t.identity.GetClientSecret())
	}
	for name, value := range options.Params {
		data.Set(name, value) // potentially overwrites data which was set before
	}
	targetURL, err := t.getURL(customerTenantHost)
	if err != nil {
		return nil, err
	}
	ctx := options.Context
	if ctx == nil {
		log.Printf("uses context.TODO as fallback, as no context is provided with RequestOptions")
		ctx = context.TODO()
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(data.Encode())) // URL-encoded payload
	if e != nil {
		return nil, &ClientError{"error performing client credentials flow", e}
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
		return nil, &ClientError{"error parsing requested client credential token", e}
	}
	return token, nil
}

func (t *TokenFlows) getURL(customerTenantHost string) (string, *ClientError) {
	if customerTenantHost == "" {
		return t.tokenURI, nil
	}
	customHost, err := url.Parse(customerTenantHost)
	if err == nil && customHost.Host != "" {
		return "https://" + customHost.Host + tokenEndpoint, nil
	}
	return "", &ClientError{"customer tenant host '" + customerTenantHost + "' can't be accepted", err}
}

func (t *TokenFlows) performRequest(r *http.Request) ([]byte, *ClientError) {
	res, err := t.options.HTTPClient.Do(r)
	if err != nil {
		return nil, &ClientError{"request to " + r.URL.String() + " failed", err}
	}
	if res.StatusCode != http.StatusOK {
		return nil, &ClientError{"request to " + r.URL.String() + " failed with status code " + res.Status, err}
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err == nil && body != nil && json.Valid(body) {
		return body, nil
	}
	return nil, &ClientError{"request to " + r.URL.String() + " provides no valid json content", err}
}

// TODO avoid duplication
func defaultTLSConfig(identity *env.Identity) (*tls.Config, *ClientError) {
	certPEMBlock := []byte(identity.GetCertificate())
	keyPEMBlock := []byte(identity.GetKey())

	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, &ClientError{"error creating x509 key pair for defaultTLSConfig", err}
	}
	tlsCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, &ClientError{"error setting up cert pool for defaultTLSConfig", err}
	}
	ok := tlsCertPool.AppendCertsFromPEM(certPEMBlock)
	if !ok {
		return nil, &ClientError{"error adding certs to pool for defaultTLSConfig", err}
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
