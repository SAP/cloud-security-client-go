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
	claimCnf             = "cnf"
	claimCnfMemberX5t    = "x5t#S256"
	claimGivenName       = "given_name"
	claimFamilyName      = "family_name"
	claimEmail           = "email"
	claimSapGlobalUserID = "user_uuid"
	claimSapGlobalZoneID = "zone_uuid" // tenant GUID
	claimIasIssuer       = "ias_iss"
)

// Token is the public API to access claims of the token
type Token interface {
	TokenValue() string                                         // TokenValue returns encoded token string
	Audience() []string                                         // Audience returns "aud" claim, if it doesn't exist empty string is returned
	Expiration() time.Time                                      // Expiration returns "exp" claim, if it doesn't exist empty string is returned
	IsExpired() bool                                            // IsExpired returns true, if 'exp' claim + leeway time of 1 minute is before current time
	IssuedAt() time.Time                                        // IssuedAt returns "iat" claim, if it doesn't exist empty string is returned
	CustomIssuer() string                                       // CustomIssuer returns "iss" claim if it is a custom domain (i.e. "ias_iss" claim available), otherwise empty string is returned
	Issuer() string                                             // Issuer returns token issuer with SAP domain; by default "iss" claim is returned or in case it is a custom domain, "ias_iss" is returned
	NotBefore() time.Time                                       // NotBefore returns "nbf" claim, if it doesn't exist empty string is returned
	Subject() string                                            // Subject returns "sub" claim, if it doesn't exist empty string is returned
	GivenName() string                                          // GivenName returns "given_name" claim, if it doesn't exist empty string is returned
	FamilyName() string                                         // FamilyName returns "family_name" claim, if it doesn't exist empty string is returned
	Email() string                                              // Email returns "email" claim, if it doesn't exist empty string is returned
	ZoneID() string                                             // ZoneID returns "zone_uuid" claim, if it doesn't exist empty string is returned
	UserUUID() string                                           // UserUUID returns "user_uuid" claim, if it doesn't exist empty string is returned
	HasClaim(claim string) bool                                 // HasClaim returns true if the provided claim exists in the token
	GetClaimAsString(claim string) (string, error)              // GetClaimAsString returns a custom claim type asserted as string. Returns error if the claim is not available or not a string.
	GetClaimAsStringSlice(claim string) ([]string, error)       // GetClaimAsStringSlice returns a custom claim type asserted as string slice. The claim name is case sensitive. Returns error if the claim is not available or not an array
	GetClaimAsMap(claim string) (map[string]interface{}, error) // GetClaimAsMap returns a map of all members and its values of a custom claim in the token. The member name is case sensitive. Returns error if the claim is not available or not a map
	GetAllClaimsAsMap() map[string]interface{}                  // GetAllClaimsAsMap returns a map of all claims contained in the token. The claim name is case sensitive. Includes also custom claims
	getJwtToken() jwt.Token
	getCnfClaimMember(memberName string) string // getCnfClaimMember returns "cnf" claim. The cnf member name is case sensitive. If it doesn't exist empty string is returned
}

type StdToken struct {
	encodedToken string
	jwtToken     jwt.Token
}

// NewToken creates a Token from an encoded jwt. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewToken(encodedToken string) (Token, error) {
	decodedToken, err := jwt.ParseString(encodedToken, jwt.WithToken(openid.New()))
	if err != nil {
		return nil, err
	}

	return StdToken{
		encodedToken: encodedToken,
		jwtToken:     decodedToken, // encapsulates jwt.token_gen from github.com/lestrrat-go/jwx/jwt
	}, nil
}

// TokenValue returns encoded token string
func (t StdToken) TokenValue() string {
	return t.encodedToken
}

func (t StdToken) Audience() []string {
	return t.jwtToken.Audience()
}

func (t StdToken) Expiration() time.Time {
	return t.jwtToken.Expiration()
}

func (t StdToken) IsExpired() bool {
	return t.Expiration().Add(1 * time.Minute).Before(time.Now())
}

func (t StdToken) IssuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

func (t StdToken) CustomIssuer() string {
	// only return iss if ias_iss does exist
	if !t.HasClaim(claimIasIssuer) {
		return ""
	}
	return t.jwtToken.Issuer()
}

func (t StdToken) Issuer() string {
	// return standard issuer if ias_iss is not set
	v, err := t.GetClaimAsString(claimIasIssuer)
	if errors.Is(err, ErrClaimNotExists) {
		return t.jwtToken.Issuer()
	}
	return v
}

func (t StdToken) NotBefore() time.Time {
	return t.jwtToken.NotBefore()
}

func (t StdToken) Subject() string {
	return t.jwtToken.Subject()
}

func (t StdToken) GivenName() string {
	v, _ := t.GetClaimAsString(claimGivenName)
	return v
}

func (t StdToken) FamilyName() string {
	v, _ := t.GetClaimAsString(claimFamilyName)
	return v
}

func (t StdToken) Email() string {
	v, _ := t.GetClaimAsString(claimEmail)
	return v
}

func (t StdToken) ZoneID() string {
	v, _ := t.GetClaimAsString(claimSapGlobalZoneID)
	return v
}

func (t StdToken) UserUUID() string {
	v, _ := t.GetClaimAsString(claimSapGlobalUserID)
	return v
}

// ErrClaimNotExists shows that the requested custom claim does not exist in the token
var ErrClaimNotExists = errors.New("claim does not exist in the token")

func (t StdToken) HasClaim(claim string) bool {
	_, exists := t.jwtToken.Get(claim)
	return exists
}

func (t StdToken) GetClaimAsString(claim string) (string, error) {
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

func (t StdToken) GetClaimAsStringSlice(claim string) ([]string, error) {
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

func (t StdToken) GetAllClaimsAsMap() map[string]interface{} {
	mapClaims, _ := t.jwtToken.AsMap(context.TODO()) // err can not really occur on jwt.Token
	return mapClaims
}

func (t StdToken) GetClaimAsMap(claim string) (map[string]interface{}, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return nil, ErrClaimNotExists
	}
	res, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to map[string]interface{}. Actual type: %T", claim, value)
	}
	return res, nil
}

func (t StdToken) getJwtToken() jwt.Token {
	return t.jwtToken
}

func (t StdToken) getCnfClaimMember(memberName string) string {
	cnfClaim, err := t.GetClaimAsMap(claimCnf)
	if errors.Is(err, ErrClaimNotExists) || cnfClaim == nil {
		return ""
	}
	res, ok := cnfClaim[memberName]
	if ok {
		return res.(string)
	}
	return ""
}
