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
	"github.com/sap-staging/cloud-security-client-go/oidcclient"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"
)

type MockServer struct {
	Server *httptest.Server
	Config *MockConfig
	RSAKey *rsa.PrivateKey
}

func NewOIDCMockServer() *MockServer {
	r := mux.NewRouter()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewTLSServer(r)

	mockServer := &MockServer{
		Server: server,
		Config: &MockConfig{
			ClientID:     "clientid",
			ClientSecret: "clientsecret",
			URL:          server.URL,
		},
		RSAKey: rsaKey,
	}

	r.HandleFunc("/.well-known/openid-configuration", mockServer.WellKnownHandler).Methods("GET")
	r.HandleFunc("/oauth2/certs", mockServer.JWKsHandler).Methods("GET")

	return mockServer
}

func (m *MockServer) WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	wellKnown := oidcclient.ProviderJSON{
		Issuer:  m.Config.URL,
		JWKsURL: fmt.Sprintf("%s/oauth2/certs", m.Server.URL),
	}
	payload, _ := json.Marshal(wellKnown)
	_, _ = w.Write(payload)
}

func (m *MockServer) JWKsHandler(w http.ResponseWriter, _ *http.Request) {
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

func (m *MockServer) SignToken(claims OIDCClaims, header map[string]interface{}) (string, error) {
	token := &jwtgo.Token{
		Header: header,
		Claims: claims,
		Method: jwtgo.SigningMethodRS256, // only faking alg header, not actual key
	}
	signedString, err := token.SignedString(m.RSAKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return signedString, nil
}

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
		UserUUID:   "11111111-2222-3333-4444-888888888888",
		GivenName:  "Foo",
		FamilyName: "Bar",
		Email:      "foo@bar.org",
	}

	return claims
}

func (m *MockServer) DefaultHeaders() map[string]interface{} {
	header := make(map[string]interface{})

	header["typ"] = "JWT"
	header[propAlg] = jwtgo.SigningMethodRS256.Alg()
	header[propKeyID] = "testKey"

	return header
}

type MockConfig struct {
	ClientID     string
	ClientSecret string
	URL          string
}

func (c MockConfig) GetClientID() string {
	return c.ClientID
}

func (c MockConfig) GetClientSecret() string {
	return c.ClientSecret
}

func (c MockConfig) GetURL() string {
	return c.URL
}
