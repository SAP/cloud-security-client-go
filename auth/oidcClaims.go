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

type OIDCClaims struct {
	jwtgo.StandardClaims
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email,omitempty"`
	ZoneID     string `json:"zone_uuid,omitempty"`
	UserUUID   string `json:"user_uuid,omitempty"`
	mapClaims  map[string]interface{}
}

func (c OIDCClaims) GetClaimAsString(claim string) (string, error) {
	s, ok := c.mapClaims[claim].(string)
	if !ok {
		return "", fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, c.mapClaims[claim])
	}
	return s, nil
}

func (c OIDCClaims) GetClaimAsStringSlice(claim string) ([]string, error) {
	s, ok := c.mapClaims[claim].([]string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, c.mapClaims[claim])
	}
	return s, nil
}
