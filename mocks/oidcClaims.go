// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package mocks

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
const (
	headerKid = "kid"
	headerAlg = "alg"
)

// OIDCClaims represents all claims that the JWT holds
type OIDCClaims struct {
	Audience   []string `json:"aud,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
	ID         string   `json:"jti,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
	IasIssuer  string   `json:"ias_iss,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	GivenName  string   `json:"given_name,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	Email      string   `json:"email,omitempty"`
	ZoneID     string   `json:"zone_uuid,omitempty"`
	AppTID     string   `json:"app_tid,omitempty"`
	UserUUID   string   `json:"user_uuid,omitempty"`
}
