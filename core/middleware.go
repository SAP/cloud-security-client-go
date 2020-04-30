package core

//TODO: Rename package to e.g. "auth"

import (
	"context"
	jwtgo "github.com/dgrijalva/jwt-go"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"time"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// external options struct because of Runaway Arguments antipattern
type Options struct {
	UserContext  string       // property under which the token is accessible in the request context. Default: "user"
	OAuthConfig  OAuthConfig  // config for the oidc server bound to the application. Default: nil
	ErrorHandler errorHandler // called when the jwt verification fails. Default: DefaultErrorHandler
	HttpClient   *http.Client // HttpClient which is used to get jwks (JSON Web Keys). Default: http.DefaultClient
}

// Config Parser for IAS can be used from env package
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetURL() string
}

type AuthMiddleware struct {
	options    Options
	parser     *jwtgo.Parser
	saasKeySet map[string]*remoteKeySet
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
	if options.HttpClient == nil {
		options.HttpClient = http.DefaultClient
		options.HttpClient.Timeout = time.Second * 30
	}
	m.options = options

	m.parser = new(jwtgo.Parser)
	m.saasKeySet = make(map[string]*remoteKeySet)

	return m
}

func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get Token from Header
		rawToken, err := extractRawToken(r)
		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}

		token, err := m.ValidateJWT(rawToken)
		if err != nil {
			m.options.ErrorHandler(w, r, err)
			return
		}
		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.options.UserContext, token.Claims))
		*r = *reqWithContext

		// Continue serving http if jwt was valid
		h.ServeHTTP(w, r)
	})
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
