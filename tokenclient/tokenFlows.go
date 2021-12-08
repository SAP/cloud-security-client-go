// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/patrickmn/go-cache"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/httpclient"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options allows configuration http(s) client
type Options struct {
	HTTPClient *http.Client // Default: basic http.Client with a timeout of 10 seconds and allowing 50 idle connections
}

// RequestOptions allows to configure the token request
type RequestOptions struct {
	// Request parameters that shall be overwritten or added to the payload
	Params map[string]string
}

// TokenFlows setup once per application.
type TokenFlows struct {
	identity env.Identity
	Options  Options
	tokenURI string
	cache    *cache.Cache
}

type request struct {
	http.Request
	key string `default:""`
}

func (r *request) cacheKey() string {
	bodyReader, err := r.GetBody()
	if err != nil {
		panic("Unexpected error, can't read request body: " + err.Error())
	}
	params, err := io.ReadAll(bodyReader)
	if err != nil {
		panic("Unexpected error, can't read request body: " + err.Error())
	}
	if r.key == "" {
		r.key = fmt.Sprintf("%v?%v", r.URL, string(params))
	}
	return r.key
}

// RequestFailedError represents a HTTP server error
type RequestFailedError struct {
	// StatusCode of failed request
	StatusCode int
	url        url.URL
	errTxt     string
}

// Error initializes RequestFailedError
func (e *RequestFailedError) Error() string {
	return fmt.Sprintf("request to '%v' failed with status code '%v' and payload: '%v'", e.url.String(), e.StatusCode, e.errTxt)
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
// options specifies rest client including tls config.
// Note: Setup of default tls config is not supported for windows os. Module crypto/x509 supports SystemCertPool with go 1.18 (https://go-review.googlesource.com/c/go/+/353589/)
func NewTokenFlows(identity env.Identity, options Options) (*TokenFlows, error) {
	t := TokenFlows{
		identity: identity,
		tokenURI: identity.GetURL() + tokenEndpoint,
		Options:  options,
		cache:    cache.New(15*time.Minute, 10*time.Minute), //nolint:gomnd
	}
	if options.HTTPClient == nil {
		tlsConfig, err := httpclient.DefaultTLSConfig(identity)
		if err != nil {
			return nil, err
		}
		t.Options.HTTPClient = httpclient.DefaultHTTPClient(tlsConfig)
	}
	return &t, nil
}

// ClientCredentials implements the client credentials flow (RFC 6749, section 4.4).
// Clients obtain an access token outside of the context of a user.
// It is used for non interactive applications (a CLI, a batch job, or for service-2-service communication) where the token is issued to the application itself,
// instead of an end user for accessing resources without principal propagation.
//
// ctx carries the request context like the deadline or other values that should be shared across API boundaries.
// customerTenantURL like "https://custom.accounts400.ondemand.com" gives the host of the customers ias tenant
// options allows to provide a request context and optionally additional request parameters
func (t *TokenFlows) ClientCredentials(ctx context.Context, customerTenantURL string, options RequestOptions) (string, error) {
	data := url.Values{}
	data.Set(clientIDParameter, t.identity.GetClientID())
	if t.identity.GetClientSecret() != "" {
		data.Set(clientSecretParameter, t.identity.GetClientSecret())
	}
	for name, value := range options.Params {
		data.Set(name, value) // potentially overwrites data which was set before
	}
	data.Set(grantTypeParameter, grantTypeClientCredentials)
	targetURL, err := t.getURL(customerTenantURL)
	if err != nil {
		return "", err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(data.Encode())) // URL-encoded payload
	if err != nil {
		return "", fmt.Errorf("error performing client credentials flow: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return t.getOrRequestToken(request{Request: *r})
}

func (t *TokenFlows) getURL(customerTenantURL string) (string, error) {
	customURL, err := url.Parse(customerTenantURL)
	if err == nil && customURL.Host != "" {
		return "https://" + customURL.Host + tokenEndpoint, nil
	}
	if !strings.HasPrefix(customerTenantURL, "http") {
		return "", fmt.Errorf("customer tenant url '%v' is not a valid url: Trying to parse a hostname without a scheme is invalid", customerTenantURL)
	}
	return "", fmt.Errorf("customer tenant url '%v' can't be parsed: %w", customerTenantURL, err)
}

func (t *TokenFlows) getOrRequestToken(r request) (string, error) {
	// token cached?
	cachedToken := t.readFromCache(&r)
	if cachedToken != "" {
		return cachedToken, nil
	}

	// request token
	var tokenRes tokenResponse
	err := t.performRequest(r, &tokenRes)
	if err != nil {
		return "", err
	}
	if tokenRes.Token == "" {
		return "", fmt.Errorf("error parsing requested client credentials token: no 'access_token' property provided")
	}

	// cache and return retrieved token
	t.writeToCache(r, tokenRes.Token)
	return t.readFromCache(&r), nil
}

func (t *TokenFlows) readFromCache(r *request) string {
	cachedEncodedToken, found := t.cache.Get(r.cacheKey())
	if !found {
		return ""
	}
	return fmt.Sprintf("%v", cachedEncodedToken)
}

func (t *TokenFlows) writeToCache(r request, token string) {
	t.cache.SetDefault(r.cacheKey(), token)
}

func (t *TokenFlows) performRequest(r request, v interface{}) error {
	res, err := t.Options.HTTPClient.Do(&r.Request)
	if err != nil {
		return fmt.Errorf("request to '%v' failed: %w", r.URL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return &RequestFailedError{res.StatusCode, *r.URL, string(body)}
	}
	if err = json.NewDecoder(res.Body).Decode(v); err != nil {
		return fmt.Errorf("error parsing response from %v: %w", r.URL, err)
	}
	return nil
}
