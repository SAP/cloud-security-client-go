package core

import (
	"context"
	"errors"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"golang.org/x/sync/singleflight"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type errorHandler func(w http.ResponseWriter, r *http.Request, err error)

// external options struct because of Runaway Arguments antipattern
type Options struct {
	UserContext  string       // property under which the token is accessible in the request context. Default: "user"
	OAuthConfig  OAuthConfig  // config for the oidc server bound to the application. Default: nil
	ErrorHandler errorHandler // called when the jwt verification fails. Default: DefaultErrorHandler
	httpClient   *http.Client // httpClient which is used to get jwks (JSON Web Keys). Default: http.DefaultClient
}

// Config Parser for IAS can be used from env package
type OAuthConfig interface {
	GetClientID() string
	GetClientSecret() string
	GetBaseURL() string
}

type AuthMiddleware struct {
	Options
	parser      *jwtgo.Parser
	saasKeySet  map[string]*remoteKeySet
	saasKeySetC sync.Map
	sf          singleflight.Group
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
	if options.httpClient == nil {
		options.httpClient = http.DefaultClient
	}
	m.Options = options

	m.parser = new(jwtgo.Parser)
	m.saasKeySet = make(map[string]*remoteKeySet)

	return m
}

func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := m.ValidateJWT(w, r)

		if err != nil {
			return
		}

		// Continue serving http if jwt was valid
		h.ServeHTTP(w, r)
	})
}

func (m *AuthMiddleware) ValidateJWT(w http.ResponseWriter, r *http.Request) error {
	// get Token from Header
	rawToken, err := extractRawToken(r)
	if err != nil {
		m.ErrorHandler(w, r, err)
		return err
	}

	token, parts, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		m.ErrorHandler(w, r, err)
		return err
	}
	token.Signature = parts[2]

	vErr := &jwtgo.ValidationError{}

	if err := m.verifySignature(token, parts); err != nil {
		err = fmt.Errorf("signature validation failed: %w", err)
		m.ErrorHandler(w, r, err)
		return err
	}

	// verify claims
	if err := token.Claims.Valid(); err != nil {
		m.ErrorHandler(w, r, err)
		return fmt.Errorf("claim check failed: %v", err)
	}

	token.Valid = vErr.Errors == 0

	if token.Valid {
		reqWithContext := r.WithContext(context.WithValue(r.Context(), m.UserContext, token.Claims))
		*r = *reqWithContext
		return nil
	}
	m.ErrorHandler(w, r, err) // call error handler specified by consumer
	return err
}

func (m *AuthMiddleware) verifySignature(t *jwtgo.Token, parts []string) error {
	iss := t.Claims.(*OIDCClaims).Issuer
	var keySet *remoteKeySet
	var ok bool
	if keySet, ok = m.saasKeySet[iss]; !ok {
		newKeySet, err, _ := m.sf.Do(iss, func() (i interface{}, err error) {
			set, err := NewKeySet(m.httpClient, iss, m.OAuthConfig)
			m.saasKeySet[iss] = set
			return set, err
		})

		if err != nil {
			return fmt.Errorf("unable to build remote keyset: %w", err)
		}
		keySet = newKeySet.(*remoteKeySet)
	}
	cachedKeys := keySet.KeysFromCache()

	if len(cachedKeys) > 0 {
		if t.Header[KEY_ID] == nil && len(cachedKeys) != 1 {
			return errors.New("no kid specified in token and more than one verification Key available")
		}
		jwk := cachedKeys[0]
		if err := t.Method.Verify(t.Raw, t.Signature, jwk.Key); err == nil {
			// valid
			return nil
		}
	}

	// if not successful, check if keys are still valid and get new keys if not -> if they should still be valid throw error
	if !time.Now().After(keySet.expiry) {
		// cached keys still valid, still verification failed
		return errors.New("failed to verify token signature")
	}

	remoteKeys, err := keySet.KeysFromRemote()
	if err != nil {
		return fmt.Errorf("failed to update token keys from remote: %w", err)
	}

	if len(remoteKeys) > 0 {
		if t.Header[KEY_ID] == nil && len(remoteKeys) != 1 {
			return errors.New("no kid specified in token and more than one verification Key available. Please contact your oidc provider")
		}
		jwk := remoteKeys[0]
		if err := t.Method.Verify(strings.Join(parts[0:2], "."), t.Signature, jwk.Key); err == nil {
			// valid
			return nil
		}
	}

	return errors.New("failed to verify token signature")
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
