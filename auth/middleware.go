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
type Options struct {
	UserContext string // UserContext property under which the token is accessible in the request context. Default: "user"

	ErrorHandler errorHandler // ErrorHandler called if the jwt verification fails. Default: DefaultErrorHandler

	HTTPClient *http.Client // HTTPClient which is used for OIDC discovery and to retrieve JWKs (JSON Web Keys). Default: basic http.Client with a timeout of 15 seconds

}

// OAuthConfig interface has to be implemented to instantiate NewAuthMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetURL() string
	GetDomain() string
}

// AuthMiddleware is the main entrypoint to the client library, instantiate with NewAuthMiddleware. It holds information about the oAuth config and configured options.
// Use either the ready to use Handler as a middleware or implement your own middleware with the help or Authenticate.
type AuthMiddleware struct {
	oAuthConfig OAuthConfig
	options     Options
	parser      *jwtgo.Parser
	oidcTenants *cache.Cache // contains *oidcclient.OIDCTenant
	sf          singleflight.Group
}

// NewAuthMiddleware instantiates a new AuthMiddleware with defaults for not provided Options.
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
		options.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
		}
	}
	m.options = options

	m.parser = new(jwtgo.Parser)
	m.oidcTenants = cache.New(12*time.Hour, 24*time.Hour)

	return m
}

// Authenticate authenticates a request and returns the Claims if successful, otherwise error
func (m *AuthMiddleware) Authenticate(r *http.Request) (*OIDCClaims, error) {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		return nil, err
	}

	token, err := m.parseAndValidateJWT(rawToken)
	if err != nil {
		return nil, err
	}

	return token.Claims.(*OIDCClaims), nil
}

// Handler implements a middleware func which takes a http.Handler and
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.Authenticate(r)

		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.options.UserContext, claims))
		*r = *reqWithContext

		// Continue serving http if jwt was valid
		next.ServeHTTP(w, r)
	})
}

// ClearCache clears the entire storage of cached oidc tenants including their JWKs
func (m *AuthMiddleware) ClearCache() {
	m.oidcTenants.Flush()
}

// DefaultErrorHandler responds with the error and HTTP status 401
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
