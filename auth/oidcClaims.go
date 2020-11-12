// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go/v4"
)

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
const (
	propKeyID = "kid"
	propAlg   = "alg"
)

// OIDCClaims represents all claims that the JWT holds
type OIDCClaims struct {
	jwtgo.StandardClaims
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email,omitempty"`
	ZoneID     string `json:"zone_uuid,omitempty"`
	UserUUID   string `json:"user_uuid,omitempty"`
	mapClaims  map[string]interface{}
}

// GetClaimAsString returns a custom claim type asserted as string. The claim name is case sensitive. Returns error if the claim is not available or not a string.
func (c OIDCClaims) GetClaimAsString(claim string) (string, error) {
	s, ok := c.mapClaims[claim]
	if !ok {
		return "", fmt.Errorf("claim %s not available not token", claim)
	}
	res, ok := s.(string)
	if !ok {
		return "", fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, c.mapClaims[claim])
	}
	return res, nil
}

// GetClaimAsStringSlice returns a custom claim type asserted as string slice. The claim name is case sensitive. Returns error if the claim is not available or not an array.
func (c OIDCClaims) GetClaimAsStringSlice(claim string) ([]string, error) {
	s, ok := c.mapClaims[claim]
	if !ok {
		return nil, fmt.Errorf("claim %s not available not token", claim)
	}
	res, ok := s.([]string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, c.mapClaims[claim])
	}
	return res, nil
}
