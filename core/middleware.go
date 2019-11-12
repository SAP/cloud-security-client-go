package core

import (
	"context"
	"github.com/dgrijalva/jwt-go/request"
	"go-cloud-security-integration/env"
	"net/http"
)

type Options struct {
	UserContext string
	env.IASConfig
}

type Middleware struct {
	Options
}

func New(userContext string, iasConfig env.IASConfig) *Middleware {
	return &Middleware{
		Options{
			UserContext: userContext,
			IASConfig:   iasConfig,
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
