package core

import (
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"net/http"
)

func extractRawToken(r *http.Request) (string, error) {
	rawToken, e := jwtRequest.AuthorizationHeaderExtractor.ExtractToken(r)
	if e != nil {
		return "", e
	}
	return rawToken, nil
}
