package core

//TODO: Move everthing related to auth to another package and keep only request/response related stuff here
//TODO: create file named after package as entry point with description of package tasks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pquerna/cachecontrol"
	"golang.org/x/sync/singleflight"
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

	httpClient   *http.Client
	singleFlight singleflight.Group
	// A set of cached keys and their expiry.
	cachedKeys []*JSONWebKey
	expiry     time.Time
}

type updateKeysResult struct {
	keys   []*JSONWebKey
	expiry time.Time
}

func NewKeySet(httpClient *http.Client, iss string, c OAuthConfig) (*remoteKeySet, error) {
	issURI, err := url.ParseRequestURI(iss)
	if err != nil {
		return nil, fmt.Errorf("unable to parse issuer URI: %s", iss)
	}
	issTrimmed := issURI.Host
	configURI, err := url.ParseRequestURI(c.GetURL())
	if err != nil {
		return nil, fmt.Errorf("unable to parse config URI: %s", c.GetURL())
	}
	configURLTrimmed := configURI.Host
	// TODO: No multitenancy support with different tenants of same auth server like accounts400
	if !strings.HasSuffix(issTrimmed, configURLTrimmed) {
		return nil, fmt.Errorf("token is issued from a different oauth server. expected to end with %s, got %s", c.GetURL(), issTrimmed)
	}
	ks := new(remoteKeySet)
	ks.httpClient = httpClient
	err = ks.performDiscovery(iss)

	if err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *remoteKeySet) GetKeys() ([]*JSONWebKey, error) {
	if !time.Now().After(ks.expiry) {
		return ks.cachedKeys, nil
		// cached keys still valid, still verification failed
	}

	rChan := ks.singleFlight.DoChan("updateKeys", ks.updateKeys)

	res := <-rChan
	if res.Err != nil {
		return nil, res.Err
	}
	keysResult := res.Val.(updateKeysResult)

	ks.expiry = keysResult.expiry
	ks.cachedKeys = keysResult.keys

	return ks.cachedKeys, nil
}

func (ks *remoteKeySet) updateKeys() (r interface{}, err error) {
	result := updateKeysResult{}
	req, err := http.NewRequest("GET", ks.jwksURL, nil)
	if err != nil {
		return result, fmt.Errorf("can't create request to fetch jwk: %v", err)
	}

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to fetch jwks from remote: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("failed to read fetched jwks: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("failed to fetch jwks: %s %s", resp.Status, body)
	}

	var keySet JSONWebKeySet
	err = unmarshalResponse(resp, body, &keySet)
	if err != nil {
		return result, fmt.Errorf("failed to decode jwks: %v %s", err, body)
	}
	for _, jwk := range keySet.Keys {
		err := jwk.assertKeyType()
		if err != nil {
			return result, fmt.Errorf("failed to build verfication Key from jwk: %v", err)
		}
	}

	result.keys = keySet.Keys

	// If the server doesn't provide cache control headers, assume the keys expire in 15min.
	result.expiry = time.Now().Add(15 * time.Minute)

	_, e, err := cachecontrol.CachableResponse(req, resp, cachecontrol.Options{})
	if err == nil && e.After(result.expiry) {
		result.expiry = e
	}

	return result, nil
}

func (ks *remoteKeySet) performDiscovery(baseURL string) error {
	wellKnown := fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(baseURL, "/"))
	req, err := http.NewRequest("GET", wellKnown, nil)
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
	ks.jwksURL = p.JWKsURL

	return nil
}

type ProviderJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKsURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

type JSONWebKeySet struct {
	Keys []*JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Kty string
	E   string
	N   string
	Use string
	Kid string
	Alg string
	Key interface{}
}

func (jwk *JSONWebKey) assertKeyType() error {
	switch jwk.Kty {
	case ktyRSA:
		NBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return err
		}
		EBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return err
		}
		jwk.Key = &rsa.PublicKey{
			N: new(big.Int).SetBytes(NBytes),
			E: int(new(big.Int).SetBytes(EBytes).Int64()),
		}
	default:
		return errors.New("jwk remote presented unsupported key type: " + jwk.Kty)
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
