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
)

const (
	ClaimCnf             = "cnf"
	ClaimCnfMemberX5t    = "x5t#S256"
	ClaimGivenName       = "given_name"
	ClaimFamilyName      = "family_name"
	ClaimEmail           = "email"
	ClaimSapGlobalUserID = "user_uuid"
	ClaimSapGlobalZoneID = "zone_uuid" // tenant GUID
	ClaimIasIssuer       = "ias_iss"
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

type stdToken struct {
	encodedToken string
	jwtToken     jwt.Token
}

// TokenValue returns encoded token string
func (t stdToken) TokenValue() string {
	return t.encodedToken
}

func (t stdToken) Audience() []string {
	return t.jwtToken.Audience()
}

func (t stdToken) Expiration() time.Time {
	return t.jwtToken.Expiration()
}

func (t stdToken) IsExpired() bool {
	return t.Expiration().Add(1 * time.Minute).Before(time.Now())
}

func (t stdToken) IssuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

func (t stdToken) CustomIssuer() string {
	// only return iss if ias_iss does exist
	if !t.HasClaim(ClaimIasIssuer) {
		return ""
	}
	return t.jwtToken.Issuer()
}

func (t stdToken) Issuer() string {
	// return standard issuer if ias_iss is not set
	v, err := t.GetClaimAsString(ClaimIasIssuer)
	if errors.Is(err, ErrClaimNotExists) {
		return t.jwtToken.Issuer()
	}
	return v
}

func (t stdToken) NotBefore() time.Time {
	return t.jwtToken.NotBefore()
}

func (t stdToken) Subject() string {
	return t.jwtToken.Subject()
}

func (t stdToken) GivenName() string {
	v, _ := t.GetClaimAsString(ClaimGivenName)
	return v
}

func (t stdToken) FamilyName() string {
	v, _ := t.GetClaimAsString(ClaimFamilyName)
	return v
}

func (t stdToken) Email() string {
	v, _ := t.GetClaimAsString(ClaimEmail)
	return v
}

func (t stdToken) ZoneID() string {
	v, _ := t.GetClaimAsString(ClaimSapGlobalZoneID)
	return v
}

func (t stdToken) UserUUID() string {
	v, _ := t.GetClaimAsString(ClaimSapGlobalUserID)
	return v
}

// ErrClaimNotExists shows that the requested custom claim does not exist in the token
var ErrClaimNotExists = errors.New("claim does not exist in the token")

func (t stdToken) HasClaim(claim string) bool {
	_, exists := t.jwtToken.Get(claim)
	return exists
}

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

func (t stdToken) GetClaimAsMap(claim string) (map[string]interface{}, error) {
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

func (t stdToken) getJwtToken() jwt.Token {
	return t.jwtToken
}

func (t stdToken) getCnfClaimMember(memberName string) string {
	cnfClaim, err := t.GetClaimAsMap(ClaimCnf)
	if errors.Is(err, ErrClaimNotExists) || cnfClaim == nil {
		return ""
	}
	res, ok := cnfClaim[memberName]
	if ok {
		return res.(string)
	}
	return ""
}
