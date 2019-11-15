package core

import (
	"context"
	"github.com/dgrijalva/jwt-go/request"
	"log"
	"net/http"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// external options struct because of Runaway Arguments antipattern
type Options struct {
	UserContext  string
	OAuthConfig  OAuthConfig
	ErrorHandler errorHandler // called when the jwt verification fails
}

// Config Parser for IAS can be used from env package
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetSbURL() string
}

type Middleware struct {
	Options
}

func New(options Options) *Middleware {
	m := new(Middleware)

	if options.OAuthConfig == nil {
		log.Fatal("OAuthConfig must not be nil, please refer to package env for default implementations")
	}
	if options.ErrorHandler == nil {
		options.ErrorHandler = DefaultErrorHandler
	}
	if options.UserContext == "" {
		options.UserContext = "user"
	}

	m.Options = options
	return m
}

func (m *Middleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := m.ValidateJWT(w, r)

		if err != nil {
			return
		}

		// Continue serving http if jwt was valid
		h.ServeHTTP(w, r)
	})
}

func (m *Middleware) ValidateJWT(w http.ResponseWriter, r *http.Request) error {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, nil, request.WithClaims(Claims{}))
	if err == nil && token.Valid {
		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.UserContext, token))
		*r = *reqWithContext
	}
	m.ErrorHandler(w, r, err) // call error handler specified by consumer
	return err
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
