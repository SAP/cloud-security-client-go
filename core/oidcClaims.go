// SPDX-FileCopyrightText: 2020 Felix Blass <felix.blass@sap.com>
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	jwtgo "github.com/dgrijalva/jwt-go/v4"
)

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
const (
	KEY_ID = "kid"

	ktyRSA = "RSA"
)

type OIDCClaims struct {
	jwtgo.StandardClaims
	UserName   string `json:"user_name,omitempty"`
	GivenName  string `json:"first_name,omitempty"`
	FamilyName string `json:"last_name,omitempty"`
	Email      string `json:"mail,omitempty"`
	ZoneId     string `json:"zone_uuid,omitempty"`
}
