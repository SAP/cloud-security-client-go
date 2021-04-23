package auth

import (
	"fmt"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"time"
)

const (
	issuer          = "iss"
	expiration      = "exp"
	audience        = "aud"
	notBefore       = "nbf"
	subject         = "sub" // to be used instead of client id
	userName        = "user_name"
	givenName       = "given_name"
	familyName      = "family_name"
	email           = "email"
	sapGlobalUserId = "user_uuid"
	sapGlobalZoneId = "zone_uuid" // tenant GUID
)

type Token interface {
	GetTokenValue() string
	setJwtToken(token jwt.Token)
	getJwtToken() jwt.Token
	Audience() []string
	Expiration() time.Time
	IsExpired() bool
	IssuedAt() time.Time
	Issuer() string
	JwtID() string
	NotBefore() time.Time
	Subject() string
	GivenName() (string, error)
	FamilyName() (string, error)
	Email() (string, error)
	ZoneId() (string, error)
	UserUUID() (string, error)
	GetClaimAsString(claim string) (string, error)
}

type StdToken struct {
	encodedToken string
	jwtToken     jwt.Token
}

func NewToken(encodedToken string) (Token, error) {
	decodedToken, err := jwt.ParseString(encodedToken, jwt.WithToken(openid.New()))
	if err != nil {
		return nil, err
	}

	return StdToken{
		encodedToken: encodedToken,
		jwtToken:     decodedToken,
	}, nil
}

//Returns encoded token string
func (t StdToken) GetTokenValue() string {
	return t.encodedToken
}

//Setter for encodedToken field
func (t StdToken) SetEncodedToken(encodedToken string) {
	t.encodedToken = encodedToken
}

//setter for jwt.Token
func (t StdToken) setJwtToken(token jwt.Token) {
	t.jwtToken = token
}

//Returns jwt.Token
func (t StdToken) getJwtToken() jwt.Token {
	return t.jwtToken
}

//Returns "aud" claim, if it doesn't exist empty string is returned
func (t StdToken) Audience() []string {
	return t.jwtToken.Audience()
}

//Returns "exp" claim, if it doesn't exist empty string is returned
func (t StdToken) Expiration() time.Time {
	return t.jwtToken.Expiration()
}

//Returns true, if 'exp' claim + leeway time of 1 minute is before current time
func (t StdToken) IsExpired() bool {
	if t.Expiration().Add(1 * time.Minute).Before(time.Now()) {
		return true
	}
	return false
}

//Returns "iat" claim, if it doesn't exist empty string is returned
func (t StdToken) IssuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

//Returns "iss" claim, if it doesn't exist empty string is returned
func (t StdToken) Issuer() string {
	return t.jwtToken.Issuer()
}

//Returns "jti" claim, if it doesn't exist empty string is returned
func (t StdToken) JwtID() string {
	return t.jwtToken.JwtID()
}

//Returns "nbf" claim, if it doesn't exist empty string is returned
func (t StdToken) NotBefore() time.Time {
	return t.jwtToken.NotBefore()
}

//Returns "sub" claim, if it doesn't exist empty string is returned
func (t StdToken) Subject() string {
	return t.jwtToken.Subject()
}

//Returns "given_name" claim, if it doesn't exist empty string is returned
func (t StdToken) GivenName() (string, error) {
	return t.GetClaimAsString(givenName)
}

//Returns "family_name" claim, if it doesn't exist empty string is returned
func (t StdToken) FamilyName() (string, error) {
	return t.GetClaimAsString(familyName)
}

//Returns "email" claim, if it doesn't exist empty string is returned
func (t StdToken) Email() (string, error) {
	return t.GetClaimAsString(email)
}

//Returns "zone_uuid" claim, if it doesn't exist empty string is returned
func (t StdToken) ZoneId() (string, error) {
	return t.GetClaimAsString(sapGlobalZoneId)
}

//Returns "user_uuid" claim, if it doesn't exist empty string is returned
func (t StdToken) UserUUID() (string, error) {
	return t.GetClaimAsString(sapGlobalUserId)
}

func (t StdToken) GetClaimAsString(claim string) (string, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return "", fmt.Errorf("claim %s not available in the token", claim)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("unable to assert claim %s type as string. Actual type: %T", claim, stringValue)
	}
	return stringValue, nil
}
