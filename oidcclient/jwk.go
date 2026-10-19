// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pquerna/cachecontrol"
	"github.com/sap/cloud-security-client-go/httpclient"
)

const defaultJwkExpiration = 15 * time.Minute
const appTIDHeader = "x-app_tid"
const clientIDHeader = "x-client_id"
const azpHeader = "x-azp"
const azpAppTIDHeader = "x-azp_app_tid"
const clientCertificateHeader = "x-client_cert"
const servicePlanHeader = "x-osb_plan"

// OIDCTenant represents one IAS tenant correlating with one app_tid and client_id with its OIDC discovery results and cached JWKs.
type OIDCTenant struct {
	ProviderJSON ProviderJSON
	httpClient   *http.Client
	jwksCache    map[jwksCacheKey]jwksCacheEntry
	mu           sync.RWMutex
}

// ClientInfo identifies the application for which IAS validates the JWK request.
type ClientInfo struct {
	ClientID string
	AppTID   string
	Azp      string
}

// JWKsRequest specifies the token and client information IAS needs to validate before it returns signing keys.
type JWKsRequest struct {
	ClientInfo
	AzpAppTID         string
	ClientCertificate string
}

// JWKsResponse contains the validation keys and, when proof token validation was requested, the consumer's service plans.
type JWKsResponse struct {
	KeySet       jwk.Set
	ServicePlans []string
}

type jwksCacheKey struct {
	clientInfo            ClientInfo
	azpAppTID             string
	clientCertificateHash string
}

type jwksCacheEntry struct {
	response JWKsResponse
	expiry   time.Time
	accepted bool
}

func (r JWKsRequest) cacheKey() jwksCacheKey {
	certificateHash := sha256.Sum256([]byte(r.ClientCertificate))
	return jwksCacheKey{
		clientInfo:            r.ClientInfo,
		azpAppTID:             r.AzpAppTID,
		clientCertificateHash: hex.EncodeToString(certificateHash[:]),
	}
}

// NewOIDCTenant instantiates a new OIDCTenant and performs the OIDC discovery.
func NewOIDCTenant(httpClient *http.Client, targetIssHost string) (*OIDCTenant, error) {
	ks := &OIDCTenant{
		httpClient: httpClient,
		jwksCache:  make(map[jwksCacheKey]jwksCacheEntry),
	}
	if err := ks.performDiscovery(targetIssHost); err != nil {
		return nil, err
	}

	return ks, nil
}

// GetJWKs returns the validation keys either cached or updated ones.
func (ks *OIDCTenant) GetJWKs(clientInfo ClientInfo) (jwk.Set, error) {
	response, err := ks.GetJWKsForRequest(JWKsRequest{ClientInfo: clientInfo})
	if err != nil {
		return nil, err
	}
	return response.KeySet, nil
}

// GetJWKsForRequest returns the validation keys and proof token service plans for a specific IAS validation request.
func (ks *OIDCTenant) GetJWKsForRequest(request JWKsRequest) (JWKsResponse, error) {
	cacheKey := request.cacheKey()
	response, err := ks.readJWKsFromMemory(cacheKey, request.ClientInfo)
	if response.KeySet != nil || err != nil {
		return response, err
	}
	return ks.updateJWKsMemory(cacheKey, request)
}

// readJWKsFromMemory returns the validation keys from memory, or an error when IAS rejected the same request.
func (ks *OIDCTenant) readJWKsFromMemory(cacheKey jwksCacheKey, clientInfo ClientInfo) (JWKsResponse, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	entry, found := ks.jwksCache[cacheKey]
	if !found || !time.Now().Before(entry.expiry) {
		return JWKsResponse{}, nil
	}
	if !entry.accepted {
		return JWKsResponse{}, fmt.Errorf("client credentials: %+v are not accepted by the identity service", clientInfo)
	}
	return cloneJWKsResponse(entry.response), nil
}

func (ks *OIDCTenant) updateJWKsMemory(cacheKey jwksCacheKey, request JWKsRequest) (JWKsResponse, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if entry, found := ks.jwksCache[cacheKey]; found && time.Now().Before(entry.expiry) {
		if !entry.accepted {
			return JWKsResponse{}, fmt.Errorf("client credentials: %+v are not accepted by the identity service", request.ClientInfo)
		}
		return cloneJWKsResponse(entry.response), nil
	}

	response, expiry, rejected, err := ks.getJWKsFromServer(request)
	if err != nil {
		// Rejecting proof requests must not let caller-supplied certificates fill the cache.
		if rejected && request.ClientCertificate == "" {
			ks.jwksCache[cacheKey] = jwksCacheEntry{expiry: expiry, accepted: false}
		}
		return JWKsResponse{}, fmt.Errorf("error updating JWKs: %v", err)
	}

	ks.jwksCache[cacheKey] = jwksCacheEntry{response: cloneJWKsResponse(response), expiry: expiry, accepted: true}
	return response, nil
}

func (ks *OIDCTenant) getJWKsFromServer(request JWKsRequest) (JWKsResponse, time.Time, bool, error) {
	result := JWKsResponse{}
	req, err := httpclient.NewRequestWithUserAgent(context.TODO(), http.MethodGet, ks.ProviderJSON.JWKsURL, http.NoBody)
	if err != nil {
		return result, time.Time{}, false, fmt.Errorf("can't create request to fetch jwk: %v", err)
	}
	// At least client-id is necessary; the remaining headers refine IAS' validation.
	req.Header.Add(clientIDHeader, request.ClientID)
	req.Header.Add(appTIDHeader, request.AppTID)
	req.Header.Add(azpHeader, request.Azp)
	if request.AzpAppTID != "" {
		req.Header.Add(azpAppTIDHeader, request.AzpAppTID)
	}
	if request.ClientCertificate != "" {
		req.Header.Add(clientCertificateHeader, request.ClientCertificate)
	}

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return result, time.Time{}, false, fmt.Errorf("failed to fetch jwks from remote: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return result, time.Time{}, false, fmt.Errorf(
				"failed to fetch jwks from remote for client credentials %+v: %v", request.ClientInfo, readErr)
		}
		return result, time.Now().Add(defaultJwkExpiration), resp.StatusCode == http.StatusBadRequest, fmt.Errorf(
			"failed to fetch jwks from remote for client credentials %+v: (%s)", request.ClientInfo, body)
	}

	keySet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return result, time.Time{}, false, fmt.Errorf("failed to parse JWK set: %w", err)
	}
	result.KeySet = keySet
	result.ServicePlans = parseServicePlans(resp.Header.Get(servicePlanHeader))

	// If the server doesn't provide cache control headers, assume the keys expire in 15min.
	expiry := time.Now().Add(defaultJwkExpiration)
	_, cacheExpiry, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err == nil && cacheExpiry.After(expiry) {
		expiry = cacheExpiry
	}
	return result, expiry, false, nil
}

func cloneJWKsResponse(response JWKsResponse) JWKsResponse {
	return JWKsResponse{
		KeySet:       response.KeySet,
		ServicePlans: append([]string(nil), response.ServicePlans...),
	}
}

func parseServicePlans(header string) []string {
	if header == "" {
		return nil
	}

	plans := strings.Split(header, ",")
	for i, plan := range plans {
		plans[i] = strings.Trim(strings.TrimSpace(plan), "\"")
	}
	return plans
}

func (ks *OIDCTenant) performDiscovery(baseURL string) error {
	wellKnown := fmt.Sprintf("https://%s/.well-known/openid-configuration", strings.TrimSuffix(baseURL, "/"))
	req, err := httpclient.NewRequestWithUserAgent(context.TODO(), http.MethodGet, wellKnown, http.NoBody)
	if err != nil {
		return fmt.Errorf("unable to construct discovery request: %v", err)
	}
	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform oidc discovery request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
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

// ProviderJSON represents data which is returned by the tenants /.well-known/openid-configuration endpoint.
type ProviderJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKsURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

func (p ProviderJSON) assertMandatoryFieldsPresent() error {
	var missing []string
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
