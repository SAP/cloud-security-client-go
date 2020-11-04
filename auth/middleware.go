// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"time"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options can be used as a argument to instantiate a AuthMiddle with NewAuthMiddleware.
//
// UserContext property under which the token is accessible in the request context. Default: "user"
//
// ErrorHandler called if the jwt verification fails. Default: DefaultErrorHandler
//
// HTTPClient which is used for OIDC discovery and to retrieve JWKs (JSON Web Keys). Default: http.DefaultClient with a timeout of 30 seconds
type Options struct {
	UserContext  string
	ErrorHandler errorHandler
	HTTPClient   *http.Client
}

// OAuthConfig interface has to be implemented to instantiate NewAuthMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetURL() string
}

type AuthMiddleware struct {
	oAuthConfig OAuthConfig
	options     Options
	parser      *jwtgo.Parser
	oidcTenants *cache.Cache // contains *oidcclient.OIDCTenant
	sf          singleflight.Group
}

func NewAuthMiddleware(oAuthConfig OAuthConfig, options Options) *AuthMiddleware {
	m := new(AuthMiddleware)

	if oAuthConfig != nil {
		m.oAuthConfig = oAuthConfig
	} else {
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
	m.oidcTenants = cache.New(12*time.Hour, 24*time.Hour)

	return m
}

func (m *AuthMiddleware) Authenticate(r *http.Request) (*OIDCClaims, error) {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		return nil, err
	}

	token, err := m.ParseAndValidateJWT(rawToken)
	if err != nil {
		return nil, err
	}

	return token.Claims.(*OIDCClaims), nil
}

func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.Authenticate(r)

		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.options.UserContext, claims))
		*r = *reqWithContext

		// Continue serving http if jwt was valid
		h.ServeHTTP(w, r)
	})
}

// Clear the entire storage of cached oidc tenants including their JWKs
func (m *AuthMiddleware) ClearCache() {
	m.oidcTenants.Flush()
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
