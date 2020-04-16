package core

//TODO: Rename package to e.g. "auth"

import (
	"context"
	"errors"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"strings"
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
	GetBaseURL() string
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

func (m *AuthMiddleware) ValidateJWT(rawToken string) (*jwtgo.Token, error) {
	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		return nil, err
	}
	token.Signature = parts[2]

	vErr := &jwtgo.ValidationError{}

	if err := m.verifySignature(token); err != nil {
		return nil, fmt.Errorf("signature validation failed: %w", err)
	}

	// verify claims
	if err := token.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("claim check failed: %v", err)
	}

	token.Valid = vErr.Errors == 0

	if token.Valid {
		return token, nil
	}
	return nil, err
}

func (m *AuthMiddleware) verifySignature(t *jwtgo.Token) error {
	claims, ok := t.Claims.(*OIDCClaims)
	if !ok {
		return fmt.Errorf("unable to assert claim type: expected *OIDCClaims, got %T", t.Claims)
	}
	iss := claims.Issuer
	var keySet *remoteKeySet
	if keySet, ok = m.saasKeySet[iss]; !ok {
		newKeySet, err, _ := m.sf.Do(iss, func() (i interface{}, err error) {
			set, err := NewKeySet(m.options.HttpClient, iss, m.options.OAuthConfig)
			m.saasKeySet[iss] = set
			return set, err
		})

		if err != nil {
			return fmt.Errorf("unable to build remote keyset: %w", err)
		}
		keySet = newKeySet.(*remoteKeySet)
	}

	jwks, err := keySet.GetKeys()
	if err != nil {
		return fmt.Errorf("failed to fetch token keys from remote: %w", err)
	}
	if len(jwks) > 0 {
		if t.Header[KEY_ID] == nil && len(jwks) != 1 {
			return errors.New("no kid specified in token and more than one verification key available")
		}
		jwk := jwks[0]
		// join token together again, as t.Raw does not contain signature
		if err := t.Method.Verify(strings.TrimSuffix(t.Raw, "."+t.Signature), t.Signature, jwk.Key); err == nil {
			// valid
			return nil
		}
	}
	return errors.New("failed to verify token signature")
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
