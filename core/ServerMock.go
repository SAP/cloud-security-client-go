// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
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

var mockServer *MockServer

func NewOIDCMockServer() *MockServer {
	r := mux.NewRouter()
	r.HandleFunc("/.well-known/openid-configuration", WellKnownHandler).Methods("GET")
	r.HandleFunc("/oauth2/certs", JWKsHandler).Methods("GET")

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewTLSServer(r)
	mockServer = &MockServer{
		Server: server,
		Config: &MockConfig{
			ClientID:     "clientid",
			ClientSecret: "clientsecret",
			URL:          server.URL,
		},
		RSAKey: rsaKey,
	}
	return mockServer
}

func WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	wellKnown := ProviderJSON{
		Issuer:  mockServer.Config.URL,
		JWKsURL: fmt.Sprintf("%s/oauth2/certs", mockServer.Server.URL),
	}
	payload, _ := json.Marshal(wellKnown)
	_, _ = w.Write(payload)
}

func JWKsHandler(w http.ResponseWriter, _ *http.Request) {
	key := &JSONWebKey{
		Kty: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(mockServer.RSAKey.PublicKey.E)).Bytes()),
		N:   base64.RawURLEncoding.EncodeToString(mockServer.RSAKey.PublicKey.N.Bytes()),
		Use: "sig",
	}
	keySet := JSONWebKeySet{Keys: []*JSONWebKey{key}}
	payload, _ := json.Marshal(keySet)
	_, _ = w.Write(payload)
}

func (m MockServer) SignToken(claims OIDCClaims) (string, error) {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	signedString, err := token.SignedString(m.RSAKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return signedString, nil
}

func (m MockServer) DefaultClaims() OIDCClaims {
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
		UserName:   "foobar",
		GivenName:  "Foo",
		FamilyName: "Bar",
		Email:      "foo@bar.org",
	}
	return claims
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
