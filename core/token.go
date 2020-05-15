package core

import (
	"errors"
	jwtgo "github.com/dgrijalva/jwt-go"
)

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
const (
	KEY_ID = "kid"

	ktyRSA = "RSA"
)

type OIDCClaims struct {
	jwtgo.StandardClaims
	//Issuer     string `json:"iss,omitempty"`
	//Expiration int64  `json:"exp,omitempty"`
	//Audience   string `json:"aud,omitempty"` // might also be []string -> convert to interface  https://github.com/dgrijalva/jwt-go/pull/355
	//Subject    string `json:"sub,omitempty"`
	//NotBefore  int64  `json:"nbf,omitempty"`
	//Id        string `json:"jti,omitempty"` // currently empty
	//IssuedAt  int64  `json:"iat,omitempty"` // currently empty
	UserName   string `json:"user_name,omitempty"`
	GivenName  string `json:"first_name,omitempty"`
	FamilyName string `json:"last_name,omitempty"`
	Email      string `json:"mail,omitempty"`
	ZoneId     string `json:"zone_uuid,omitempty"`
}

// Deprecated
func (c OIDCClaims) Valid() error {
	return errors.New("Not implemented. Please use the validateClaims func")
}
