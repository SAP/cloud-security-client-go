// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
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

// MockServer instantiates a new MockServer.
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
			Domain:       domain.Host,
		},
		RSAKey: rsaKey,
	}

	r.HandleFunc("/.well-known/openid-configuration", mockServer.WellKnownHandler).Methods("GET")
	r.HandleFunc("/oauth2/certs", mockServer.JWKsHandler).Methods("GET")

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

// WellKnownHandler is the http handler which answers requests to the mock servers OIDC discovery endpoint.
func (m *MockServer) JWKsHandler(w http.ResponseWriter, _ *http.Request) {
	m.JWKsHitCounter++
	key := &oidcclient.JSONWebKey{
		Kid: "testKey",
		Kty: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.RSAKey.PublicKey.E)).Bytes()),
		N:   base64.RawURLEncoding.EncodeToString(m.RSAKey.PublicKey.N.Bytes()),
		Use: "sig",
	}
	keySet := oidcclient.JSONWebKeySet{Keys: []*oidcclient.JSONWebKey{key}}
	payload, _ := json.Marshal(keySet)
	_, _ = w.Write(payload)
}

// SignToken signs the provided OIDCClaims and header fields into a base64 encoded JWT token signed by the MockServer.
func (m *MockServer) SignToken(claims OIDCClaims, header map[string]interface{}) (string, error) {
	token := &jwtgo.Token{
		Header: header,
		Claims: claims,
		Method: jwtgo.SigningMethodRS256,
	}
	return m.signToken(token)
}

// Sign token with additional non-standard oidc claims. additionalClaims must not contain any oidc standard claims or duplicates.
// See also: SignToken
func (m *MockServer) SignTokenWithAdditionalClaims(claims OIDCClaims, additionalClaims map[string]interface{}, header map[string]interface{}) (string, error) {
	mapClaims := jwtgo.MapClaims{}

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

	token := &jwtgo.Token{
		Header: header,
		Claims: mapClaims,
		Method: jwtgo.SigningMethodRS256,
	}
	return m.signToken(token)
}

func (m *MockServer) signToken(token *jwtgo.Token) (string, error) {
	signedString, err := token.SignedString(m.RSAKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %v", err)
	}
	return signedString, nil
}

// DefaultClaims returns OIDCClaims with mock server specific default values for standard OIDC claims.
func (m *MockServer) DefaultClaims() OIDCClaims {
	now := jwtgo.Now()
	iss := m.Server.URL
	aud := jwtgo.ClaimStrings{m.Config.ClientID}
	claims := OIDCClaims{
		StandardClaims: jwtgo.StandardClaims{
			Audience:  aud,
			ExpiresAt: jwtgo.At(now.Add(time.Minute * 5)),
			ID:        uuid.New().String(),
			IssuedAt:  now,
			Issuer:    iss,
			NotBefore: now,
		},
		GivenName:  "Foo",
		FamilyName: "Bar",
		Email:      "foo@bar.org",
		ZoneID:     "11111111-2222-3333-4444-888888888888",
		UserUUID:   "22222222-3333-4444-5555-666666666666",
	}
	return claims
}

// DefaultClaims returns JWT headers with mock server specific default values.
func (m *MockServer) DefaultHeaders() map[string]interface{} {
	header := make(map[string]interface{})

	header["typ"] = "JWT"
	header[propAlg] = jwtgo.SigningMethodRS256.Alg()
	header[propKeyID] = "testKey"

	return header
}

// MockConfig represents the credentials to the mock server
type MockConfig struct {
	ClientID     string
	ClientSecret string
	URL          string
	Domain       string
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

// GetDomain implements the auth.OAuthConfig interface.
func (c MockConfig) GetDomain() string {
	return c.Domain
}
