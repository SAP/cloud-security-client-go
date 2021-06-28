// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"time"
)

// The ContextKey type is used as a key for library related values in the go context. See also TokenCtxKey
type ContextKey int

// TokenCtxKey is the key that holds the authorization value (*OIDCClaims) in the request context
const (
	TokenCtxKey ContextKey = 0

	cacheExpiration      = 12 * time.Hour
	cacheCleanupInterval = 24 * time.Hour
)

// ErrorHandler is the type for the Error Handler which is called on unsuccessful token validation and if the AuthenticationHandler middleware func is used
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options can be used as a argument to instantiate a AuthMiddle with NewMiddleware.
type Options struct {
	ErrorHandler ErrorHandler // ErrorHandler called if the jwt verification fails and the AuthenticationHandler middleware func is used. Default: DefaultErrorHandler
	HTTPClient   *http.Client // HTTPClient which is used for OIDC discovery and to retrieve JWKs (JSON Web Keys). Default: basic http.Client with a timeout of 15 seconds
}

// OAuthConfig interface has to be implemented to instantiate NewMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type OAuthConfig interface {
	GetClientID() string             // Returns the client id of the oAuth client.
	GetClientSecret() string         // Returns the client secret. Optional
	GetURL() string                  // Returns the url to the Identity tenant. E.g. https://abcdefgh.accounts.ondemand.com
	GetDomains() []string            // Returns the domains of the Identity service. E.g. ["accounts.ondemand.com"]
	GetZoneUUID() uuid.UUID          // Returns the zone uuid. Optional
	GetProofTokenURL() string        // Returns the proof token url. Optional
	GetCertificate() string          // Returns the client certificate. Optional
	GetKey() string                  // Returns the client certificate key. Optional
	GetCertificateExpiresAt() string // Returns the client certificate expiration time. Optional
}

// TokenFromCtx retrieves the claims of a request which
// have been injected before via the auth middleware
func TokenFromCtx(r *http.Request) Token {
	return r.Context().Value(TokenCtxKey).(Token)
}

// Middleware is the main entrypoint to the client library, instantiate with NewMiddleware. It holds information about the oAuth config and configured options.
// Use either the ready to use AuthenticationHandler as a middleware or implement your own middleware with the help of Authenticate.
type Middleware struct {
	oAuthConfig OAuthConfig
	options     Options
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

	m.oidcTenants = cache.New(cacheExpiration, cacheCleanupInterval)

	return m
}

// Authenticate authenticates a request and returns the Token if validation was successful, otherwise error is returned
func (m *Middleware) Authenticate(r *http.Request) (Token, error) {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		return nil, err
	}

	token, err := m.parseAndValidateJWT(rawToken)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// AuthenticationHandler authenticates a request and injects the claims into
// the request context. If the authentication (see Authenticate) does not succeed,
// the specified error handler (see Options.ErrorHandler) will be called and
// the current request will stop.
func (m *Middleware) AuthenticationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.Authenticate(r)

		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), TokenCtxKey, token))
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
