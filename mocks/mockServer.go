// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sap/cloud-security-client-go/oidcclient"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

// MockServer serves as a single tenant OIDC mock server for tests.
// Requests to the MockServer must be done by the mockServers client: MockServer.Server.Client()
type MockServer struct {
	Server              *httptest.Server // Server holds the httptest.Server and its Client.
	Config              *MockConfig      // Config holds the OIDC config which applications bind to the application.
	RSAKey              *rsa.PrivateKey  // RSAKey holds the servers private key to sign tokens.
	WellKnownHitCounter int              // JWKsHitCounter holds the number of requests to the WellKnownHandler.
	JWKsHitCounter      int              // JWKsHitCounter holds the number of requests to the JWKsHandler.
}

// NewOIDCMockServer instantiates a new MockServer.
func NewOIDCMockServer() (*MockServer, error) {
	r := mux.NewRouter()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to create mock server: error generating rsa key: %v", err)
	}
	server := httptest.NewTLSServer(r)

	domain, err := url.Parse(server.URL)
	if err != nil {
		return nil, fmt.Errorf("unable to create mock server: error parsing server url: %v", err)
	}
	mockServer := &MockServer{
		Server: server,
		Config: &MockConfig{
			ClientID:     "clientid",
			ClientSecret: "clientsecret",
			URL:          server.URL,
			Domains:      []string{domain.Host},
		},
		RSAKey: rsaKey,
	}

	r.HandleFunc("/.well-known/openid-configuration", mockServer.WellKnownHandler).Methods("GET")
	r.HandleFunc("/oauth2/certs", mockServer.JWKsHandler).Methods("GET").Headers("x-zone_uuid", mockServer.DefaultClaims().ZoneID)
	r.HandleFunc("/oauth2/certs", mockServer.JWKsHandlerInvalidZone).Methods("GET").Headers("x-zone_uuid", "22222222-3333-4444-5555-666666666666")

	return mockServer, nil
}

// ClearAllHitCounters resets all http handlers hit counters. See MockServer.WellKnownHitCounter and MockServer.JWKsHitCounter
func (m *MockServer) ClearAllHitCounters() {
	m.WellKnownHitCounter = 0
	m.JWKsHitCounter = 0
}

// WellKnownHandler is the http handler which answers requests to the mock servers OIDC discovery endpoint.
func (m *MockServer) WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	// TODO: make response configurable for better tests (well_known and jwks)
	m.WellKnownHitCounter++
	wellKnown := oidcclient.ProviderJSON{
		Issuer:  m.Config.URL,
		JWKsURL: fmt.Sprintf("%s/oauth2/certs", m.Server.URL),
	}
	payload, _ := json.Marshal(wellKnown)
	_, _ = w.Write(payload)
}

// JWKsHandler is the http handler which answers requests to the JWKS endpoint.
func (m *MockServer) JWKsHandler(w http.ResponseWriter, _ *http.Request) {
	m.JWKsHitCounter++
	key := &JSONWebKey{
		Kid: "testKey",
		Kty: "RSA",
		Alg: "RS256",
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.RSAKey.PublicKey.E)).Bytes()),
		N:   base64.RawURLEncoding.EncodeToString(m.RSAKey.PublicKey.N.Bytes()),
		Use: "sig",
	}
	keySet := JSONWebKeySet{Keys: []*JSONWebKey{key}}
	payload, _ := json.Marshal(keySet)
	_, _ = w.Write(payload)
}

// JWKsHandlerInvalidZone is the http handler which answers invalid requests to the JWKS endpoint.
// in reality it returns "{ \"msg\":\"Invalid zone_uuid provided\" }"
func (m *MockServer) JWKsHandlerInvalidZone(w http.ResponseWriter, _ *http.Request) {
	m.JWKsHitCounter++
	w.WriteHeader(400)
}

// SignToken signs the provided OIDCClaims and header fields into a base64 encoded JWT token signed by the MockServer.
func (m *MockServer) SignToken(claims OIDCClaims, header map[string]interface{}) (string, error) {
	var mapClaims map[string]interface{}

	dataBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to convert OIDCClaims to map (marshal): %v", err)
	}
	err = json.Unmarshal(dataBytes, &mapClaims)
	if err != nil {
		return "", fmt.Errorf("unable to convert OIDCClaims to map (unmarshal): %v", err)
	}

	jwtToken := jwt.New()

	for k, v := range mapClaims {
		err := jwtToken.Set(k, v)
		if err != nil {
			return "", fmt.Errorf("unable to convert OIDCClaims to map: %v", err)
		}
	}

	return m.signToken(jwtToken, header)
}

// SignTokenWithAdditionalClaims signs the token with additional non-standard oidc claims. additionalClaims must not contain any oidc standard claims or duplicates.
// See also: SignToken
func (m *MockServer) SignTokenWithAdditionalClaims(claims OIDCClaims, additionalClaims, header map[string]interface{}) (string, error) {
	var mapClaims map[string]interface{}

	dataBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to convert OIDCClaims to map (marshal): %v", err)
	}
	err = json.Unmarshal(dataBytes, &mapClaims)
	if err != nil {
		return "", fmt.Errorf("unable to convert OIDCClaims to map (unmarshal): %v", err)
	}

	for k, v := range additionalClaims {
		if _, exists := mapClaims[k]; exists {
			return "", fmt.Errorf("additional claims must not contain any OIDC standard claims or duplicates. use claims parameter instead")
		}
		mapClaims[k] = v
	}
	token := jwt.New()

	for k, v := range mapClaims {
		err := token.Set(k, v)
		if err != nil {
			return "", fmt.Errorf("unable to convert OIDCClaims to map: %v", err)
		}
	}

	return m.signToken(token, header)
}

func (m *MockServer) signToken(token jwt.Token, header map[string]interface{}) (string, error) {
	jwkKey, err := jwk.New(m.RSAKey)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK: %s", err)
	}

	_ = jwkKey.Set(jwk.KeyIDKey, header[headerKid])

	signedJwt, err := jwt.Sign(token, jwa.RS256, jwkKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign the token: %v", err)
	}

	var alg, ok = header[headerAlg].(jwa.SignatureAlgorithm)
	if !ok || alg != jwa.RS256 {
		signedJwt, _ = modifySignedJwtHeader(signedJwt, header)
	}

	return string(signedJwt), nil
}
func modifySignedJwtHeader(signed []byte, headerMap map[string]interface{}) ([]byte, error) {
	_, payload, signature, err := jws.SplitCompact(signed)
	if err != nil {
		return nil, fmt.Errorf("failed to modify Jwt signature: %s", err)
	}

	headers := jws.NewHeaders()
	_ = headers.Set(jws.AlgorithmKey, headerMap[headerAlg])
	_ = headers.Set(jws.KeyIDKey, headerMap[headerKid])

	marshaledHeaders, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to modify Jwt signature: %s", err)
	}
	encodedHeaders := make([]byte, base64.RawURLEncoding.EncodedLen(len(marshaledHeaders)))
	base64.RawURLEncoding.Encode(encodedHeaders, marshaledHeaders)

	signedWithModifiedHeaders := bytes.Join([][]byte{encodedHeaders, payload, signature}, []byte{'.'})

	return signedWithModifiedHeaders, nil
}

// DefaultClaims returns OIDCClaims with mock server specific default values for standard OIDC claims.
func (m *MockServer) DefaultClaims() OIDCClaims {
	now := time.Now().Unix()
	after5min := now + 5*60*1000
	claims := OIDCClaims{

		Audience:   []string{m.Config.ClientID},
		ExpiresAt:  after5min,
		ID:         uuid.New().String(),
		IssuedAt:   now,
		Issuer:     m.Server.URL,
		NotBefore:  now,
		GivenName:  "Foo",
		FamilyName: "Bar",
		Email:      "foo@bar.org",
		ZoneID:     "11111111-2222-3333-4444-888888888888",
		UserUUID:   "22222222-3333-4444-5555-666666666666",
	}
	return claims
}

// DefaultHeaders returns JWT headers with mock server specific default values.
func (m *MockServer) DefaultHeaders() map[string]interface{} {
	header := make(map[string]interface{})

	header["typ"] = "JWT"
	header[headerAlg] = jwa.RS256
	header[headerKid] = "testKey"

	return header
}

// MockConfig represents the credentials to the mock server
type MockConfig struct {
	ClientID             string
	ClientSecret         string
	URL                  string
	Domains              []string
	ZoneUUID             uuid.UUID
	ProofTokenURL        string
	OsbURL               string
	Certificate          string
	Key                  string
	CertificateExpiresAt string
}

// GetClientID implements the auth.OAuthConfig interface.
func (c MockConfig) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the auth.OAuthConfig interface.
func (c MockConfig) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the auth.OAuthConfig interface.
func (c MockConfig) GetURL() string {
	return c.URL
}

// GetDomains implements the auth.OAuthConfig interface.
func (c MockConfig) GetDomains() []string {
	return c.Domains
}

// GetZoneUUID implements the auth.OAuthConfig interface.
func (c MockConfig) GetZoneUUID() uuid.UUID {
	return c.ZoneUUID
}

// GetProofTokenURL implements the auth.OAuthConfig interface.
func (c MockConfig) GetProofTokenURL() string {
	return c.ProofTokenURL
}

// GetOsbURL implements the auth.OAuthConfig interface.
func (c MockConfig) GetOsbURL() string {
	return c.OsbURL
}

// GetCertificate implements the auth.OAuthConfig interface.
func (c MockConfig) GetCertificate() string {
	return c.Certificate
}

// GetKey implements the auth.OAuthConfig interface.
func (c MockConfig) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the auth.OAuthConfig interface.
func (c MockConfig) GetCertificateExpiresAt() string {
	return c.CertificateExpiresAt
}

// JSONWebKeySet represents the data which is returned by the tenants /oauth2/certs endpoint
type JSONWebKeySet struct {
	Keys []*JSONWebKey `json:"keys"`
}

// JSONWebKey represents a single JWK
type JSONWebKey struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Key interface{}
}
