package core

import (
	"context"
	"errors"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"time"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// external options struct because of Runaway Arguments antipattern
type Options struct {
	UserContext  string
	OAuthConfig  OAuthConfig
	ErrorHandler errorHandler // called when the jwt verification fails
	httpClient   *http.Client // httpClient which is used to get jwks (JSON Web Keys)
}

// Config Parser for IAS can be used from env package
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetBaseURL() string
}

type Middleware struct {
	Options
	parser     *jwtgo.Parser
	saasKeySet map[string]*remoteKeySet
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
	if options.httpClient == nil {
		options.httpClient = http.DefaultClient
	}
	m.Options = options

	m.parser = new(jwtgo.Parser)

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
	// get Token from Header
	// parse Token into struct -> Refer to other package for structure (Signature, Raw, Claims, ..)
	rawToken, err := extractRawToken(r)
	if err != nil {
		m.ErrorHandler(w, r, err)
		return err
	}

	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		// throw err
		return err
	}
	token.Signature = parts[2]

	err = m.verifySignature(token)

	// verify claims
	if err := token.Claims.Valid(); err != nil {
		return fmt.Errorf("claim check failed: %v", err)
	}

	if err == nil && token.Valid {
		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.UserContext, token))
		*r = *reqWithContext
		return nil
	}
	m.ErrorHandler(w, r, err) // call error handler specified by consumer
	return err
}

func (m *Middleware) verifySignature(t *jwtgo.Token) error {
	iss := t.Claims.(OIDCClaims).Issuer
	var keySet *remoteKeySet
	var ok bool
	if keySet, ok = m.saasKeySet[iss]; !ok {
		newKeySet, err := NewKeySet(m.httpClient, iss, m.OAuthConfig)
		if err != nil {
			return fmt.Errorf("unable to build remote keyset: %v", err)
		}
		m.saasKeySet[iss] = newKeySet
		keySet = newKeySet
	}
	cachedKeys := keySet.KeysFromCache()

	if len(cachedKeys) > 0 {
		if t.Header[KEY_ID] == nil && len(cachedKeys) != 1 {
			return errors.New("no kid specified in token and more than one verification key available")
		}
		jwk := cachedKeys[0]
		if err := t.Method.Verify(t.Raw, t.Signature, jwk.key); err == nil {
			// valid
			return nil
		}
	}

	// if not successful, check if keys are still valid and get new keys if not -> if they should still be valid throw error
	if !time.Now().After(keySet.expiry) {
		// cached keys still valid, still verification failed
		return errors.New("failed to verify token signature")
	}

	remoteKeys, err := keySet.KeysFromRemote(m.httpClient)
	if err != nil {

	}

	if len(remoteKeys) > 0 {
		if t.Header[KEY_ID] == nil && len(remoteKeys) != 1 {
			return errors.New("no kid specified in token and more than one verification key available")
		}
		jwk := remoteKeys[0]
		if err := t.Method.Verify(t.Raw, t.Signature, jwk.key); err == nil {
			// valid
			return nil
		}
	}

	return errors.New("failed to verify token signature")
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
