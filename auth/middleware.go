// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"github.com/sap-staging/cloud-security-client-go/oidcClient"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"time"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options can be used as a argument to instantiate a AuthMiddle with NewAuthMiddleware.
type Options struct {
	UserContext  string       // property under which the token is accessible in the request context. Default: "user"
	OAuthConfig  OAuthConfig  // config for the oidc server bound to the application. Default: nil
	ErrorHandler errorHandler // called when the jwt verification fails. Default: DefaultErrorHandler
	HTTPClient   *http.Client // HTTPClient which is used to get jwks (JSON Web Keys). Default: http.DefaultClient
}

// OAuthConfig interface has to be implemented to be used in Options. For IAS the standard implementation from env package can be used.
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetURL() string
}

type AuthMiddleware struct {
	options    Options
	parser     *jwtgo.Parser
	saasKeySet map[string]*oidcClient.RemoteKeySet
	sf         singleflight.Group
}

func NewAuthMiddleware(options Options) *AuthMiddleware {
	m := new(AuthMiddleware)

	if options.OAuthConfig == nil {
		log.Fatal("OAuthConfig must not be nil, please refer to package env for default implementations")
	}
	if options.ErrorHandler == nil {
		options.ErrorHandler = DefaultErrorHandler
	}
	if options.UserContext == "" {
		options.UserContext = "user"
	}
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
		options.HTTPClient.Timeout = time.Second * 30
	}
	m.options = options

	m.parser = new(jwtgo.Parser)
	m.saasKeySet = make(map[string]*oidcClient.RemoteKeySet)

	return m
}

func (m *AuthMiddleware) Authenticate(r *http.Request) AuthResult {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		return AuthResult{false, err, nil}
	}

	token, err := m.ParseAndValidateJWT(rawToken)
	if err != nil {
		return AuthResult{false, err, nil}
	}

	return AuthResult{true, nil, token.Claims.(*OIDCClaims)}
}

func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authResult := m.Authenticate(r)

		if !authResult.success {
			m.options.ErrorHandler(w, r, authResult.error)
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.options.UserContext, authResult.Details))
		*r = *reqWithContext

		// Continue serving http if jwt was valid
		h.ServeHTTP(w, r)
	})
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
