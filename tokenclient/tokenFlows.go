// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package tokenclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/httpclient"
	"github.com/sap/cloud-security-client-go/oidcclient"
)

// Options allows configuration http(s) client
type Options struct {
	HTTPClient *http.Client // Default: basic http.Client with a timeout of 10 seconds and allowing 50 idle connections
}

// RequestOptions allows to configure the token request
type RequestOptions struct {
	// Request parameters that shall be overwritten or added to the payload
	Params map[string]string
	// TokenEndpoint overrides /oauth2/token with an absolute path on the trusted tenant.
	TokenEndpoint string
}

// TokenFlows setup once per application.
type TokenFlows struct {
	identity   env.Identity
	Options    Options
	cache      *cache.Cache
	oidcConfig *cache.Cache
}

type request struct {
	http.Request
	key string
}

func (r *request) cacheKey() (string, error) {
	if r.key == "" {
		bodyReader, err := r.GetBody()
		if err != nil {
			return "", fmt.Errorf("unexpected error, can't read request body: %w", err)
		}
		params, err := io.ReadAll(bodyReader)
		if err != nil {
			return "", fmt.Errorf("unexpected error, can't read request body: %w", err)
		}
		r.key = fmt.Sprintf("%v?%v", r.URL, string(params))
	}
	return r.key, nil
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
		identity:   identity,
		Options:    options,
		cache:      cache.New(15*time.Minute, 10*time.Minute),
		oidcConfig: cache.New(15*time.Minute, 10*time.Minute),
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
// Clients obtain an access token outside the context of a user.
// It is used for non-interactive applications (a CLI, a batch job, or for service-2-service communication) where the token is issued to the application itself,
// instead of an end user for accessing resources without principal propagation.
//
// ctx carries the request context like the deadline or other values that should be shared across API boundaries.
// customerTenantURL like "https://custom.accounts400.ondemand.com" gives the host of the customers ias tenant. Its
// host must belong to one of the trusted domains of the bound identity service.
// options allows additional request parameters and an absolute token endpoint path on that tenant.
func (t *TokenFlows) ClientCredentials(ctx context.Context, customerTenantURL string, options RequestOptions) (string, error) {
	targetURL, err := t.getURL(customerTenantURL, options)
	if err != nil {
		return "", err
	}
	return t.clientCredentials(ctx, targetURL, options.Params)
}

// ClientCredentialsWithDiscovery obtains a client credentials token using the tenant's OIDC token_endpoint.
// Both the tenant and the discovered endpoint must use HTTPS and belong to the identity's trusted domains.
// Pass identity.GetURL() as customerTenantURL to use the bound tenant, or a trusted subscriber tenant URL.
func (t *TokenFlows) ClientCredentialsWithDiscovery(ctx context.Context, customerTenantURL string, params map[string]string) (string, error) {
	tenantURL, err := t.tenantURL(customerTenantURL)
	if err != nil {
		return "", err
	}
	targetURL, err := t.tokenEndpointFor(ctx, tenantURL.Host)
	if err != nil {
		return "", err
	}
	return t.clientCredentials(ctx, targetURL, params)
}

func (t *TokenFlows) clientCredentials(ctx context.Context, targetURL string, params map[string]string) (string, error) {
	data := url.Values{}
	data.Set(clientIDParameter, t.identity.GetClientID())
	if t.identity.GetClientSecret() != "" {
		data.Set(clientSecretParameter, t.identity.GetClientSecret())
	}
	for name, value := range params {
		data.Set(name, value) // potentially overwrites data which was set before
	}
	data.Set(grantTypeParameter, grantTypeClientCredentials)
	r, err := httpclient.NewRequestWithUserAgent(ctx, http.MethodPost, targetURL, strings.NewReader(data.Encode())) // URL-encoded payload
	if err != nil {
		return "", fmt.Errorf("error performing client credentials flow: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return t.getOrRequestToken(request{Request: *r})
}

func (t *TokenFlows) tokenEndpointFor(ctx context.Context, host string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if cached, found := t.oidcConfig.Get(host); found {
		return cached.(string), nil
	}
	tenant, err := oidcclient.NewOIDCTenantWithContext(ctx, t.Options.HTTPClient, host)
	if err != nil {
		return "", fmt.Errorf("error retrieving oidc configuration from customer tenant url 'https://%v': %w", host, err)
	}
	if tenant.ProviderJSON.TokenURL == "" {
		return "", fmt.Errorf("oidc configuration of customer tenant url 'https://%v' does not provide a token_endpoint", host)
	}
	endpoint, err := t.trustedURL(tenant.ProviderJSON.TokenURL, "token_endpoint")
	if err != nil {
		return "", err
	}
	t.oidcConfig.SetDefault(host, endpoint.String())
	return endpoint.String(), nil
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
	return tokenRes.Token, err
}

func (t *TokenFlows) readFromCache(r *request) string {
	cacheKey, err := r.cacheKey()
	if err != nil {
		return ""
	}
	cachedEncodedToken, found := t.cache.Get(cacheKey)
	if !found {
		return ""
	}
	return fmt.Sprintf("%v", cachedEncodedToken)
}

func (t *TokenFlows) writeToCache(r request, token string) {
	cacheKey, err := r.cacheKey()
	if err != nil {
		log.Fatalf("Write to Cache is skipped. Unexpected error to determine cache key: %s", err.Error())
		return
	}
	t.cache.SetDefault(cacheKey, token)
}

func (t *TokenFlows) performRequest(r request, v interface{}) error {
	res, err := httpclient.WithoutRedirects(t.Options.HTTPClient).Do(&r.Request)
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
