// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"time"
)

// OIDCHeaderBuilder can construct header fields for test cases
type OIDCHeaderBuilder struct {
	header map[string]interface{}
}

// NewOIDCHeaderBuilder instantiates a new OIDCHeaderBuilder with a base (e.g. MockServer.DefaultHeaders)
func NewOIDCHeaderBuilder(base map[string]interface{}) *OIDCHeaderBuilder {
	b := &OIDCHeaderBuilder{base}
	return b
}

// KeyID sets the keyID field
func (b *OIDCHeaderBuilder) KeyID(keyID string) *OIDCHeaderBuilder {
	if keyID == "" {
		b.header[propKeyID] = nil
	} else {
		b.header[propKeyID] = keyID
	}
	return b
}

// Alg sets the alg field
func (b *OIDCHeaderBuilder) Alg(alg string) *OIDCHeaderBuilder {
	if alg == "" {
		b.header[propAlg] = nil
	} else {
		b.header[propAlg] = alg
	}
	return b
}

// Build returns the finished http header fields
func (b *OIDCHeaderBuilder) Build() map[string]interface{} {
	return b.header
}

// OIDCHeaderBuilder can construct token claims for test cases
type OIDCClaimsBuilder struct {
	claims OIDCClaims
}

// NewOIDCClaimsBuilder instantiates a new OIDCClaimsBuilder with a base (e.g. MockServer.DefaultClaims)
func NewOIDCClaimsBuilder(base OIDCClaims) *OIDCClaimsBuilder {
	b := &OIDCClaimsBuilder{base}
	return b
}

// Build returns the finished token OIDCClaims
func (b *OIDCClaimsBuilder) Build() OIDCClaims {
	return b.claims
}

// Audience sets the aud field
func (b *OIDCClaimsBuilder) Audience(aud ...string) *OIDCClaimsBuilder {
	b.claims.Audience = aud
	return b
}

// ExpiresAt sets the exp field
func (b *OIDCClaimsBuilder) ExpiresAt(expiresAt time.Time) *OIDCClaimsBuilder {
	b.claims.ExpiresAt = jwtgo.At(expiresAt)
	return b
}

// ID sets the id field
func (b *OIDCClaimsBuilder) ID(id string) *OIDCClaimsBuilder {
	b.claims.ID = id
	return b
}

// IssuedAt sets the iat field
func (b *OIDCClaimsBuilder) IssuedAt(issuedAt time.Time) *OIDCClaimsBuilder {
	b.claims.IssuedAt = jwtgo.At(issuedAt)
	return b
}

// Issuer sets the iss field
func (b *OIDCClaimsBuilder) Issuer(issuer string) *OIDCClaimsBuilder {
	b.claims.Issuer = issuer
	return b
}

// NotBefore sets the nbf field
func (b *OIDCClaimsBuilder) NotBefore(notBefore time.Time) *OIDCClaimsBuilder {
	b.claims.NotBefore = jwtgo.At(notBefore)
	return b
}

// Subject sets the sub field
func (b *OIDCClaimsBuilder) Subject(subject string) *OIDCClaimsBuilder {
	b.claims.Subject = subject
	return b
}

// UserUUID sets the user_uuid field
func (b *OIDCClaimsBuilder) UserUUID(userUUID string) *OIDCClaimsBuilder {
	b.claims.UserUUID = userUUID
	return b
}

// GivenName sets the given_name field
func (b *OIDCClaimsBuilder) GivenName(givenName string) *OIDCClaimsBuilder {
	b.claims.GivenName = givenName
	return b
}

// FamilyName sets the family_name field
func (b *OIDCClaimsBuilder) FamilyName(familyName string) *OIDCClaimsBuilder {
	b.claims.FamilyName = familyName
	return b
}

// Email sets the email field
func (b *OIDCClaimsBuilder) Email(email string) *OIDCClaimsBuilder {
	b.claims.Email = email
	return b
}

// ZoneID sets the zone_uuid field
func (b *OIDCClaimsBuilder) ZoneID(zoneID string) *OIDCClaimsBuilder {
	b.claims.ZoneID = zoneID
	return b
}

// WithoutIssuedAt removes the aud claim
func (b *OIDCClaimsBuilder) WithoutAudience() *OIDCClaimsBuilder {
	b.claims.Audience = nil
	return b
}

// WithoutIssuedAt removes the exp claim
func (b *OIDCClaimsBuilder) WithoutExpiresAt() *OIDCClaimsBuilder {
	b.claims.ExpiresAt = nil
	return b
}

// WithoutIssuedAt removes the iat claim
func (b *OIDCClaimsBuilder) WithoutIssuedAt() *OIDCClaimsBuilder {
	b.claims.IssuedAt = nil
	return b
}

// WithoutNotBefore removes the nbf claim
func (b *OIDCClaimsBuilder) WithoutNotBefore() *OIDCClaimsBuilder {
	b.claims.NotBefore = nil
	return b
}
