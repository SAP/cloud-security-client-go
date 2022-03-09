// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/singleflight"

	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/httpclient"
	"github.com/sap/cloud-security-client-go/tokenclient"
)

// The ContextKey type is used as a key for library related values in the go context. See also TokenCtxKey
type ContextKey int

// TokenCtxKey is the key that holds the authorization value (*OIDCClaims) in the request context
// ClientCertificateCtxKey is the key that holds the x509 client certificate in the request context
const (
	TokenCtxKey             ContextKey = 0
	ClientCertificateCtxKey ContextKey = 1
	cacheExpiration                    = 12 * time.Hour
	cacheCleanupInterval               = 24 * time.Hour
)

// ErrorHandler is the type for the Error Handler which is called on unsuccessful token validation and if the AuthenticationHandler middleware func is used
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options can be used as a argument to instantiate a AuthMiddle with NewMiddleware.
type Options struct {
	ErrorHandler ErrorHandler // ErrorHandler called if the jwt verification fails and the AuthenticationHandler middleware func is used. Default: DefaultErrorHandler
	HTTPClient   *http.Client // HTTPClient which is used for OIDC discovery and to retrieve JWKs (JSON Web Keys). Default: basic http.Client with a timeout of 15 seconds
}

// TokenFromCtx retrieves the claims of a request which
// have been injected before via the auth middleware
func TokenFromCtx(r *http.Request) Token {
	return r.Context().Value(TokenCtxKey).(Token)
}

// ClientCertificateFromCtx retrieves the X.509 client certificate of a request which
// have been injected before via the auth middleware
func ClientCertificateFromCtx(r *http.Request) *Certificate {
	return r.Context().Value(ClientCertificateCtxKey).(*Certificate)
}

// Middleware is the main entrypoint to the authn client library, instantiate with NewMiddleware. It holds information about the oAuth config and configured options.
// Use either the ready to use AuthenticationHandler as a middleware or implement your own middleware with the help of Authenticate.
type Middleware struct {
	identity    env.Identity
	options     Options
	oidcTenants *cache.Cache // contains *oidcclient.OIDCTenant
	sf          singleflight.Group
	tokenFlows  *tokenclient.TokenFlows
}

// NewMiddleware instantiates a new Middleware with defaults for not provided Options.
func NewMiddleware(identity env.Identity, options Options) *Middleware {
	m := new(Middleware)

	if identity != nil {
		m.identity = identity
	} else {
		log.Fatal("identity must not be nil, please refer to package env for default implementations")
	}
	if options.ErrorHandler == nil {
		options.ErrorHandler = DefaultErrorHandler
	}
	if options.HTTPClient == nil {
		tlsConfig, err := httpclient.DefaultTLSConfig(identity)
		if err != nil {
			log.Fatal("identity config provides invalid certificate/key: %w", err)
		}
		options.HTTPClient = httpclient.DefaultHTTPClient(tlsConfig)
	}
	m.options = options

	m.oidcTenants = cache.New(cacheExpiration, cacheCleanupInterval)

	return m
}

// GetTokenFlows creates or returns TokenFlows, otherwise error is returned
func (m *Middleware) GetTokenFlows() (*tokenclient.TokenFlows, error) {
	if m.tokenFlows == nil {
		tokenFlows, err := tokenclient.NewTokenFlows(m.identity, tokenclient.Options{HTTPClient: m.options.HTTPClient})
		if err != nil {
			return nil, err
		}
		m.tokenFlows = tokenFlows
	}
	return m.tokenFlows, nil
}

// Authenticate authenticates a request and returns the Token if validation was successful, otherwise error is returned
func (m *Middleware) Authenticate(r *http.Request) (Token, error) {
	token, _, err := m.AuthenticateWithProofOfPossession(r)

	return token, err
}

// AuthenticateWithProofOfPossession authenticates a request and returns the Token and the client certificate if validation was successful,
// otherwise error is returned
func (m *Middleware) AuthenticateWithProofOfPossession(r *http.Request) (Token, *Certificate, error) {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		return Token{}, nil, err
	}

	token, err := m.parseAndValidateJWT(rawToken)
	if err != nil {
		return Token{}, nil, err
	}

	const forwardedClientCertHeader = "x-forwarded-client-cert"
	var cert *Certificate
	cert, err = newCertificate(r.Header.Get(forwardedClientCertHeader))
	if err != nil {
		return Token{}, nil, err
	}
	if "1" == "" && cert != nil { // TODO integrate proof of possession into middleware
		err = validateCertificate(cert, token)
		if err != nil {
			return Token{}, nil, err
		}
	}

	return token, cert, nil
}

// AuthenticationHandler authenticates a request and injects the claims into
// the request context. If the authentication (see Authenticate) does not succeed,
// the specified error handler (see Options.ErrorHandler) will be called and
// the current request will stop.
// In case of successful authentication the request context is enriched with the token,
// as well as the client certificate (if given).
func (m *Middleware) AuthenticationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, cert, err := m.AuthenticateWithProofOfPossession(r)

		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		ctx := context.WithValue(context.WithValue(r.Context(), TokenCtxKey, token), ClientCertificateCtxKey, cert)
		*r = *r.WithContext(ctx)

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
