// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

const (
	givenName       = "given_name"
	familyName      = "family_name"
	email           = "email"
	sapGlobalUserID = "user_uuid"
	sapGlobalZoneID = "zone_uuid" // tenant GUID
	iasIssuer       = "ias_iss"
)

// Token is the public API to access claims of the token
type Token interface {
	TokenValue() string                                   // TokenValue returns encoded token string
	GivenName() string                                    // GivenName returns "given_name" claim, if it doesn't exist empty string is returned
	FamilyName() string                                   // FamilyName returns "family_name" claim, if it doesn't exist empty string is returned
	Email() string                                        // Email returns "email" claim, if it doesn't exist empty string is returned
	ZoneID() string                                       // ZoneID returns "zone_uuid" claim, if it doesn't exist empty string is returned
	UserUUID() string                                     // UserUUID returns "user_uuid" claim, if it doesn't exist empty string is returned
	GetClaimAsString(claim string) (string, error)        // GetClaimAsString returns a custom claim type asserted as string. Returns error if the claim is not available or not a string.
	GetClaimAsStringSlice(claim string) ([]string, error) // GetClaimAsStringSlice returns a custom claim type asserted as string slice. The claim name is case sensitive. Returns error if the claim is not available or not an array
	GetAllClaimsAsMap() map[string]interface{}            // GetAllClaimsAsMap returns a map of all claims contained in the token. The claim name is case sensitive. Includes also custom claims
	// only for internal usage
	audience() []string    // audience returns "aud" claim, if it doesn't exist empty string is returned
	expiration() time.Time // expiration returns "exp" claim, if it doesn't exist empty string is returned
	isExpired() bool       // isExpired returns true, if 'exp' claim + leeway time of 1 minute is before current time
	issuedAt() time.Time   // issuedAt returns "iat" claim, if it doesn't exist empty string is returned
	issuer() string        // issuer returns "iss" claim, if it doesn't exist empty string is returned
	iasIssuer() string     // iasIssuer returns "ias_iss" (only set if custom domains are used) claim, if it doesn't exist the value of Issuer() returned
	notBefore() time.Time  // notBefore returns "nbf" claim, if it doesn't exist empty string is returned
	subject() string       // subject returns "sub" claim, if it doesn't exist empty string is returned
	getJwtToken() jwt.Token
}

type stdToken struct {
	encodedToken string
	jwtToken     jwt.Token
}

// NewToken creates a Token from an encoded jwt. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewToken(encodedToken string) (Token, error) {
	decodedToken, err := jwt.ParseString(encodedToken, jwt.WithToken(openid.New()))
	if err != nil {
		return nil, err
	}

	return stdToken{
		encodedToken: encodedToken,
		jwtToken:     decodedToken, // encapsulates jwt.token_gen from github.com/lestrrat-go/jwx/jwt
	}, nil
}

// TokenValue returns encoded token string
func (t stdToken) TokenValue() string {
	return t.encodedToken
}

func (t stdToken) audience() []string {
	return t.jwtToken.Audience()
}

func (t stdToken) expiration() time.Time {
	return t.jwtToken.Expiration()
}

func (t stdToken) isExpired() bool {
	return t.expiration().Add(1 * time.Minute).Before(time.Now())
}

func (t stdToken) issuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

func (t stdToken) issuer() string {
	return t.jwtToken.Issuer()
}

func (t stdToken) iasIssuer() string {
	// return standard issuer if ias_iss is not set
	v, err := t.GetClaimAsString(iasIssuer)
	if errors.Is(err, ErrClaimNotExists) {
		return t.issuer()
	}
	return v
}

func (t stdToken) notBefore() time.Time {
	return t.jwtToken.NotBefore()
}

func (t stdToken) subject() string {
	return t.jwtToken.Subject()
}

func (t stdToken) GivenName() string {
	v, _ := t.GetClaimAsString(givenName)
	return v
}

func (t stdToken) FamilyName() string {
	v, _ := t.GetClaimAsString(familyName)
	return v
}

func (t stdToken) Email() string {
	v, _ := t.GetClaimAsString(email)
	return v
}

func (t stdToken) ZoneID() string {
	v, _ := t.GetClaimAsString(sapGlobalZoneID)
	return v
}

func (t stdToken) UserUUID() string {
	v, _ := t.GetClaimAsString(sapGlobalUserID)
	return v
}

// ErrClaimNotExists shows that the requested custom claim does not exist in the token
var ErrClaimNotExists = errors.New("claim does not exist in the token")

func (t stdToken) GetClaimAsString(claim string) (string, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return "", ErrClaimNotExists
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("unable to assert claim %s type as string. Actual type: %T", claim, value)
	}
	return stringValue, nil
}

func (t stdToken) GetClaimAsStringSlice(claim string) ([]string, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return nil, ErrClaimNotExists
	}
	res, ok := value.([]string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, value)
	}
	return res, nil
}

func (t stdToken) GetAllClaimsAsMap() map[string]interface{} {
	mapClaims, _ := t.jwtToken.AsMap(context.TODO()) // err can not really occur on jwt.Token
	return mapClaims
}

func (t stdToken) getJwtToken() jwt.Token {
	return t.jwtToken
}
