// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pquerna/cachecontrol"
	"golang.org/x/sync/singleflight"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultJwkExpiration = 15 * time.Minute

// OIDCTenant represents one IAS tenant with it's OIDC discovery results and cached JWKs
type OIDCTenant struct {
	ProviderJSON ProviderJSON

	httpClient   *http.Client
	singleFlight singleflight.Group
	// A set of cached keys and their expiry.
	jwks       jwk.Set
	jwksExpiry time.Time
}

type updateKeysResult struct {
	keys   jwk.Set
	expiry time.Time
}

// NewOIDCTenant instantiates a new OIDCTenant and performs the OIDC discovery
func NewOIDCTenant(httpClient *http.Client, targetIss *url.URL) (*OIDCTenant, error) {
	ks := new(OIDCTenant)
	ks.httpClient = httpClient

	err := ks.performDiscovery(targetIss.Host)
	if err != nil {
		return nil, err
	}

	return ks, nil
}

// GetJWKs returns the validation keys either cached or updated ones
func (ks *OIDCTenant) GetJWKs() (jwk.Set, error) {
	if time.Now().Before(ks.jwksExpiry) {
		return ks.jwks, nil
	}

	updatedKeys, err, _ := ks.singleFlight.Do("updateKeys", ks.updateKeys)
	if err != nil {
		return nil, fmt.Errorf("error updating JWKs: %v", err)
	}
	keysResult := updatedKeys.(updateKeysResult)

	ks.jwksExpiry = keysResult.expiry
	ks.jwks = keysResult.keys

	return ks.jwks, nil
}

func (ks *OIDCTenant) updateKeys() (r interface{}, err error) {
	result := updateKeysResult{}
	req, err := http.NewRequestWithContext(context.TODO(), "GET", ks.ProviderJSON.JWKsURL, nil)
	if err != nil {
		return result, fmt.Errorf("can't create request to fetch jwk: %v", err)
	}

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to fetch jwks from remote: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("failed to fetch jwks: http %s", resp.Status)
	}

	jwks, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %w", err)
	}

	result.keys = jwks
	// If the server doesn't provide cache control headers, assume the keys expire in 15min.
	result.expiry = time.Now().Add(defaultJwkExpiration)

	_, e, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err == nil && e.After(result.expiry) {
		result.expiry = e
	}

	return result, nil
}

func (ks *OIDCTenant) performDiscovery(baseURL string) error {
	wellKnown := fmt.Sprintf("https://%s/.well-known/openid-configuration", strings.TrimSuffix(baseURL, "/"))
	req, err := http.NewRequestWithContext(context.TODO(), "GET", wellKnown, nil)
	if err != nil {
		return fmt.Errorf("unable to construct discovery request: %v", err)
	}
	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform oidc discovery request: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p ProviderJSON
	err = unmarshalResponse(resp, body, &p)
	if err != nil {
		return fmt.Errorf("failed to decode provider discovery object: %v", err)
	}
	err = p.assertMandatoryFieldsPresent()
	if err != nil {
		return fmt.Errorf("oidc discovery for %v failed: %v", wellKnown, err)
	}
	ks.ProviderJSON = p

	return nil
}

// ProviderJSON represents data which is returned by the tenants /.well-known/openid-configuration endpoint
type ProviderJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKsURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

func (p ProviderJSON) assertMandatoryFieldsPresent() error {
	missing := make([]string, 0, 2)
	if p.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if p.JWKsURL == "" {
		missing = append(missing, "jwks_uri")
	}
	if len(missing) > 0 {
		str := "'" + strings.Join(missing, "','") + "'"
		return fmt.Errorf("missing following mandatory fields in the OIDC discovery response: %v", str)
	}
	return nil
}

func unmarshalResponse(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}

	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
