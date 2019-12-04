package core

import (
	jwtgo "github.com/dgrijalva/jwt-go"
)

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims

const ALGORITHM = "alg"
const JWKS_URL = "jku"
const KEY_ID = "kid"
const TYPE = "typ"

const ISSUER = "iss"
const EXPIRATION = "exp"
const AUDIENCE = "aud"
const SUBJECT = "sub"
const NOT_BEFORE = "nbf"
const USER_NAME = "user_name"
const GIVEN_NAME = "first_name"
const FAMILY_NAME = "last_name"
const EMAIL = "mail"

const ktyRSA = "RSA"

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
}

//
func (c OIDCClaims) Valid() error {
	err := c.StandardClaims.Valid()
	if err != nil {
		return err
	}
	// TODO: check aud and iss additionally to StandardClaims check
	//c.VerifyAudience()
	//c.VerifyIssuer()
	return nil
}
