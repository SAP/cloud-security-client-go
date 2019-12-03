package core

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pquerna/cachecontrol"
	"io/ioutil"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type remoteKeySet struct {
	jwksURL string

	// A set of cached keys and their expiry.
	cachedKeys []JSONWebKey
	expiry     time.Time
}

func NewKeySet(httpClient *http.Client, iss string, c OAuthConfig) (*remoteKeySet, error) {
	address, err := url.Parse(iss)
	if err != nil {
		return nil, fmt.Errorf("unable to parse iss url from token: %v", err)
	}
	if !strings.EqualFold(address.Hostname(), c.GetBaseURL()) {
		return nil, fmt.Errorf("token is issued from a different oauth server. expected %s, got %s", c.GetBaseURL(), address.Hostname())
	}
	subdomain := strings.TrimSuffix(address.Hostname(), c.GetBaseURL())
	ks := new(remoteKeySet)
	err = ks.performDiscovery(httpClient, c.GetBaseURL(), subdomain)

	if err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *remoteKeySet) KeysFromRemote(httpClient *http.Client) ([]JSONWebKey, error) {
	req, err := http.NewRequest("GET", ks.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("can't create request to fetch jwk: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks from remote: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read fetched jwks: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch jwks: %s %s", resp.Status, body)
	}

	var keySet JSONWebKeySet
	err = unmarshalResponse(resp, body, &keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwks: %v %s", err, body)
	}
	for _, jwk := range keySet.Keys {
		err := jwk.assertKeyType()
		if err != nil {
			return nil, fmt.Errorf("failed to build verfication key from jwk: %v", err)
		}
	}

	// If the server doesn't provide cache control headers, assume the
	// keys expire immediately.
	expiry := time.Now()

	_, e, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err == nil && e.After(expiry) {
		expiry = e
	}

	ks.expiry = expiry
	ks.cachedKeys = keySet.Keys

	return ks.cachedKeys, nil
}

func (ks *remoteKeySet) KeysFromCache() []JSONWebKey {
	return ks.cachedKeys
}

func (ks *remoteKeySet) performDiscovery(httpClient *http.Client, baseURL string, subdomain string) error {
	wellKnown := strings.TrimSuffix(baseURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return fmt.Errorf("unable to construct discovery request: %v", err)
	}
	resp, err := httpClient.Do(req)
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

	var p providerJSON
	err = unmarshalResponse(resp, body, &p)
	if err != nil {
		return fmt.Errorf("failed to decode provider discovery object: %v", err)
	}
	return nil
}

type providerJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	kty string
	e   string
	n   string
	use string
	kid string
	alg string
	key interface{}
}

func (jwk *JSONWebKey) assertKeyType() error {
	switch jwk.alg {
	case ktyRSA:
		NBytes, err := base64.RawURLEncoding.DecodeString(jwk.n)
		if err != nil {
			return
		}
		EBytes, err := base64.RawURLEncoding.DecodeString(jwk.e)
		if err != nil {
			return
		}
		jwk.key = &rsa.PublicKey{
			N: new(big.Int).SetBytes(NBytes),
			E: int(new(big.Int).SetBytes(EBytes).Int64()),
		}
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
