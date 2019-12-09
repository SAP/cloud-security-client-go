package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httptest"
	"strings"
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
			BaseURL:      strings.TrimLeft(server.URL, "https://"),
		},
		RSAKey: rsaKey,
	}
	return mockServer
}

func WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	wellKnown := ProviderJSON{
		Issuer:  "mytenant." + mockServer.Config.BaseURL,
		JWKsURL: fmt.Sprintf("%s/oauth2/certs", mockServer.Server.URL),
	}
	payload, _ := json.Marshal(wellKnown)
	_, _ = w.Write(payload)
}

func JWKsHandler(w http.ResponseWriter, _ *http.Request) {
	eBytes := make([]byte, 64)
	_ = binary.PutVarint(eBytes, int64(mockServer.RSAKey.PublicKey.E))
	key := &JSONWebKey{
		Kty: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
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
	now := time.Now()
	iss := "mytenant." + m.Config.BaseURL
	claims := OIDCClaims{
		StandardClaims: jwtgo.StandardClaims{
			Audience:  "",
			ExpiresAt: now.Add(time.Minute * 5).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  now.Unix(),
			Issuer:    iss,
			NotBefore: now.Unix(),
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
	BaseURL      string
}

func (c MockConfig) GetClientID() string {
	return c.ClientID
}

func (c MockConfig) GetClientSecret() string {
	return c.ClientSecret
}

func (c MockConfig) GetBaseURL() string {
	return c.BaseURL
}
