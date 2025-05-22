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
	claimSapGlobalAppTID = "app_tid"
	claimIasIssuer       = "ias_iss"
	claimAzp             = "azp"
	claimScimID          = "scim_id"
	claimGroups          = "groups"
	claimIasAPIs         = "ias_apis"
)

type Token struct {
	encodedToken string
	jwtToken     jwt.Token
}

// NewToken creates a Token from an encoded jwt. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewToken(encodedToken string) (Token, error) {
	decodedToken, err := jwt.ParseString(encodedToken, jwt.WithToken(openid.New()))
	if err != nil {
		return Token{}, err
	}

	return Token{
		encodedToken: encodedToken,
		jwtToken:     decodedToken, // encapsulates jwt.token_gen from github.com/lestrrat-go/jwx/jwt
	}, nil
}

// TokenValue returns encoded token string
func (t Token) TokenValue() string {
	return t.encodedToken
}

// Audience returns "aud" claim, if it doesn't exist empty string is returned
func (t Token) Audience() []string {
	return t.jwtToken.Audience()
}

// Expiration returns "exp" claim, if it doesn't exist empty string is returned
func (t Token) Expiration() time.Time {
	return t.jwtToken.Expiration()
}

// IsExpired returns true, if 'exp' claim + leeway time of 1 minute is before current time
func (t Token) IsExpired() bool {
	return t.Expiration().Add(1 * time.Minute).Before(time.Now())
}

// IssuedAt returns "iat" claim, if it doesn't exist empty string is returned
func (t Token) IssuedAt() time.Time {
	return t.jwtToken.IssuedAt()
}

// CustomIssuer returns "iss" claim if it is a custom domain (i.e. "ias_iss" claim available), otherwise empty string is returned
func (t Token) CustomIssuer() string {
	// only return iss if ias_iss does exist
	if !t.HasClaim(claimIasIssuer) {
		return ""
	}
	return t.jwtToken.Issuer()
}

// Issuer returns token issuer with SAP domain; by default "iss" claim is returned or in case it is a custom domain, "ias_iss" is returned
func (t Token) Issuer() string {
	// return standard issuer if ias_iss is not set
	v, err := t.GetClaimAsString(claimIasIssuer)
	if errors.Is(err, ErrClaimNotExists) {
		return t.jwtToken.Issuer()
	}
	return v
}

// NotBefore returns "nbf" claim, if it doesn't exist empty string is returned
func (t Token) NotBefore() time.Time {
	return t.jwtToken.NotBefore()
}

// Subject returns "sub" claim, if it doesn't exist empty string is returned
func (t Token) Subject() string {
	return t.jwtToken.Subject()
}

// GivenName returns "given_name" claim, if it doesn't exist empty string is returned
func (t Token) GivenName() string {
	v, _ := t.GetClaimAsString(claimGivenName)
	return v
}

// FamilyName returns "family_name" claim, if it doesn't exist empty string is returned
func (t Token) FamilyName() string {
	v, _ := t.GetClaimAsString(claimFamilyName)
	return v
}

// Email returns "email" claim, if it doesn't exist empty string is returned
func (t Token) Email() string {
	v, _ := t.GetClaimAsString(claimEmail)
	return v
}

// ZoneID returns "app_tid" claim, if it doesn't exist empty string is returned
// Deprecated: is replaced by AppTID and will be removed with the next major release
func (t Token) ZoneID() string {
	appTID := t.AppTID()
	if appTID == "" {
		zoneUUID, _ := t.GetClaimAsString(claimSapGlobalZoneID)
		return zoneUUID
	}
	return appTID
}

// AppTID returns "app_tid" claim, if it doesn't exist empty string is returned
func (t Token) AppTID() string {
	appTID, _ := t.GetClaimAsString(claimSapGlobalAppTID)
	return appTID
}

// Azp returns "azp" claim, if it doesn't exist empty string is returned
func (t Token) Azp() string {
	appTID, _ := t.GetClaimAsString(claimAzp)
	return appTID
}

// UserUUID returns "user_uuid" claim, if it doesn't exist empty string is returned
func (t Token) UserUUID() string {
	v, _ := t.GetClaimAsString(claimSapGlobalUserID)
	return v
}

// ScimID returns "scim_id" claim, if it doesn't exist empty string is returned
func (t Token) ScimID() string {
	v, _ := t.GetClaimAsString(claimScimID)
	return v
}

// Groups returns "groups" claim, if it doesn't exist empty string is returned
func (t Token) Groups() []string {
	v, _ := t.GetClaimAsStringSlice(claimGroups)
	return v
}

// ErrClaimNotExists shows that the requested custom claim does not exist in the token
var ErrClaimNotExists = errors.New("claim does not exist in the token")

// HasClaim returns true if the provided claim exists in the token
func (t Token) HasClaim(claim string) bool {
	_, exists := t.jwtToken.Get(claim)
	return exists
}

// GetClaimAsString returns a custom claim type asserted as string. Returns error if the claim is not available or not a string.
func (t Token) GetClaimAsString(claim string) (string, error) {
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

// GetClaimAsStringSlice returns a custom claim type asserted as string slice. The claim name is case-sensitive. Returns error if the claim is not available or not an array
func (t Token) GetClaimAsStringSlice(claim string) ([]string, error) {
	value, exists := t.jwtToken.Get(claim)
	if !exists {
		return nil, ErrClaimNotExists
	}
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []interface{}:
		strArr := make([]string, len(v))
		for i, elem := range v {
			strVal, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("unable to assert array element as string. Actual type: %T", elem)
			}
			strArr[i] = strVal
		}
		return strArr, nil
	case []string:
		return v, nil
	default:
		return nil, fmt.Errorf("unable to assert claim %s type as string or []string. Actual type: %T", claim, value)
	}
}

// GetAllClaimsAsMap returns a map of all claims contained in the token. The claim name is case sensitive. Includes also custom claims
func (t Token) GetAllClaimsAsMap() map[string]interface{} {
	mapClaims, _ := t.jwtToken.AsMap(context.TODO()) // err can not really occur on jwt.Token
	return mapClaims
}

// GetClaimAsMap returns a map of all members and its values of a custom claim in the token. The member name is case sensitive. Returns error if the claim is not available or not a map
func (t Token) GetClaimAsMap(claim string) (map[string]interface{}, error) {
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

func (t Token) getJwtToken() jwt.Token {
	return t.jwtToken
}

func (t Token) getCnfClaimMember(memberName string) string {
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
