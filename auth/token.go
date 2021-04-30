// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"time"
)

const (
	givenName       = "given_name"
	familyName      = "family_name"
	email           = "email"
	sapGlobalUserID = "user_uuid"
	sapGlobalZoneID = "zone_uuid" // tenant GUID
)

type Token interface {
	GetTokenValue() string
	getJwtToken() jwt.Token
	Audience() []string
	Expiration() time.Time
	IsExpired() bool
	IssuedAt() time.Time
	Issuer() string
	NotBefore() time.Time
	Subject() string
	GivenName() (string, error)
	FamilyName() (string, error)
	Email() (string, error)
	ZoneID() (string, error)
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

// Returns encoded token string
func (t StdToken) GetTokenValue() string {
	return t.encodedToken
}

// Setter for encodedToken field
func (t StdToken) SetEncodedToken(encodedToken string) {
	t.encodedToken = encodedToken
}

// Returns jwt.Token
func (t StdToken) getJwtToken() jwt.Token {
	return t.jwtToken
}

// Returns "aud" claim, if it doesn't exist empty string is returned
func (t StdToken) Audience() []string {
	return t.jwtToken.Audience()
}

// Returns "exp" claim, if it doesn't exist empty string is returned
func (t StdToken) Expiration() time.Time {
	return t.jwtToken.Expiration()
}

// Returns true, if 'exp' claim + leeway time of 1 minute is before current time
func (t StdToken) IsExpired() bool {
	return t.Expiration().Add(1 * time.Minute).Before(time.Now())
}

// Returns "iat" claim, if it doesn't exist empty string is returned
func (t StdToken) IssuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

// Returns "iss" claim, if it doesn't exist empty string is returned
func (t StdToken) Issuer() string {
	return t.jwtToken.Issuer()
}

// Returns "nbf" claim, if it doesn't exist empty string is returned
func (t StdToken) NotBefore() time.Time {
	return t.jwtToken.NotBefore()
}

// Returns "sub" claim, if it doesn't exist empty string is returned
func (t StdToken) Subject() string {
	return t.jwtToken.Subject()
}

// Returns "given_name" claim, if it doesn't exist empty string is returned
func (t StdToken) GivenName() (string, error) {
	return t.GetClaimAsString(givenName)
}

// Returns "family_name" claim, if it doesn't exist empty string is returned
func (t StdToken) FamilyName() (string, error) {
	return t.GetClaimAsString(familyName)
}

// Returns "email" claim, if it doesn't exist empty string is returned
func (t StdToken) Email() (string, error) {
	return t.GetClaimAsString(email)
}

// Returns "zone_uuid" claim, if it doesn't exist empty string is returned
func (t StdToken) ZoneID() (string, error) {
	return t.GetClaimAsString(sapGlobalZoneID)
}

// Returns "user_uuid" claim, if it doesn't exist empty string is returned
func (t StdToken) UserUUID() (string, error) {
	return t.GetClaimAsString(sapGlobalUserID)
}

func (t StdToken) GetClaimAsString(claim string) (string, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return "", fmt.Errorf("claim %s not available in the token", claim)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("unable to assert claim %s type as string. Actual type: %T", claim, value)
	}
	return stringValue, nil
}
