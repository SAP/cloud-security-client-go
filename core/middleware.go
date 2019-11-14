package core

import (
	"context"
	"github.com/dgrijalva/jwt-go/request"
	"net/http"
)

// external options struct because of Runaway Arguments antipattern
type Options struct {
	UserContext string
	OAuthConfig OAuthConfig
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
	return &Middleware{
		Options{
			UserContext: options.UserContext,
			OAuthConfig: options.OAuthConfig,
		},
	}
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
	return nil
}
