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

// The ContextKey type is used as a key for library related values in the go context. See also UserContextKey
type ContextKey int

// UserContextKey is the key that holds the authorization value (*OIDCClaims) in the request context
const UserContextKey ContextKey = 0

// ErrorHandler is the type for the Error Handler which is called on unsuccessful token validation and if the Handler middleware func is used
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options can be used as a argument to instantiate a AuthMiddle with NewMiddleware.
type Options struct {
	ErrorHandler ErrorHandler // ErrorHandler called if the jwt verification fails and the Handler middleware func is used. Default: DefaultErrorHandler
	HTTPClient   *http.Client // HTTPClient which is used for OIDC discovery and to retrieve JWKs (JSON Web Keys). Default: basic http.Client with a timeout of 15 seconds
}

// OAuthConfig interface has to be implemented to instantiate NewMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetURL() string
	GetDomain() string
}

// GetClaims retrieves the claims of a request which
// have been injected before via the auth middleware
func GetClaims(r *http.Request) *OIDCClaims {
	return r.Context().Value(UserContextKey).(*OIDCClaims)
}

// Middleware is the main entrypoint to the client library, instantiate with NewMiddleware. It holds information about the oAuth config and configured options.
// Use either the ready to use Handler as a middleware or implement your own middleware with the help of Authenticate.
type Middleware struct {
	oAuthConfig OAuthConfig
	options     Options
	parser      *jwtgo.Parser
	oidcTenants *cache.Cache // contains *oidcclient.OIDCTenant
	sf          singleflight.Group
}

// NewMiddleware instantiates a new Middleware with defaults for not provided Options.
func NewMiddleware(oAuthConfig OAuthConfig, options Options) *Middleware {
	m := new(Middleware)

	if oAuthConfig != nil {
		m.oAuthConfig = oAuthConfig
	} else {
		log.Fatal("OAuthConfig must not be nil, please refer to package env for default implementations")
	}
	if options.ErrorHandler == nil {
		options.ErrorHandler = DefaultErrorHandler
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
func (m *Middleware) Authenticate(r *http.Request) (*OIDCClaims, error) {
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
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.Authenticate(r)

		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), UserContextKey, claims))
		*r = *reqWithContext

		// Continue serving http if jwt was valid
		next.ServeHTTP(w, r)
	})
}

// ClearCache clears the entire storage of cached oidc tenants including their JWKs
func (m *Middleware) ClearCache() {
	m.oidcTenants.Flush()
}

// DefaultErrorHandler responds with the error and HTTP status 401
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
