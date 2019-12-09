package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.wdf.sap.corp/CPSecurity/go-cloud-security-integration/core"
	"net/http"
	"net/http/httptest"
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
