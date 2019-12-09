package test

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
	"github.wdf.sap.corp/CPSecurity/go-cloud-security-integration/core"
	"net/http"
	"net/http/httptest"
	"time"
)

type MockServer struct {
	Server *httptest.Server
	RSAKey *rsa.PrivateKey
}

var mockServer *MockServer

func NewOIDCMockServer() *MockServer {
	r := mux.NewRouter()
	r.HandleFunc("/.well-known/openid-configuration", WellKnownHandler).Methods("GET")
	r.HandleFunc("/oauth2/certs", JWKsHandler).Methods("GET")

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockServer = &MockServer{
		Server: httptest.NewTLSServer(r),
		RSAKey: rsaKey,
	}
	return mockServer
}

func WellKnownHandler(w http.ResponseWriter, _ *http.Request) {
	wellKnown := core.ProviderJSON{
		Issuer:  "",
		JWKsURL: fmt.Sprintf("%s/oauth2/certs", mockServer.Server.URL),
	}
	payload, _ := json.Marshal(wellKnown)
	_, _ = w.Write(payload)
}

func JWKsHandler(w http.ResponseWriter, _ *http.Request) {
	eBytes := make([]byte, 64)
	_ = binary.PutVarint(eBytes, int64(mockServer.RSAKey.PublicKey.E))
	key := &core.JSONWebKey{
		Kty: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
		N:   base64.RawURLEncoding.EncodeToString(mockServer.RSAKey.PublicKey.N.Bytes()),
		Use: "sig",
	}
	keySet := core.JSONWebKeySet{Keys: []*core.JSONWebKey{key}}
	payload, _ := json.Marshal(keySet)
	_, _ = w.Write(payload)
}

func (m MockServer) SignToken(claims core.OIDCClaims) (string, error) {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	signedString, err := token.SignedString(m.RSAKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return signedString, nil
}

func (m MockServer) DefaultClaims() core.OIDCClaims {
	now := time.Now()
	claims := core.OIDCClaims{
		StandardClaims: jwtgo.StandardClaims{
			Audience:  "",
			ExpiresAt: now.Add(time.Minute * 5).Unix(),
			Id:        uuid.New().String(),
			IssuedAt:  now.Unix(),
			Issuer:    m.Server.URL,
			NotBefore: now.Unix(),
		},
		UserName:   "foobar",
		GivenName:  "Foo",
		FamilyName: "Bar",
		Email:      "foo@bar.org",
	}
	return claims
}
