// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"time"
)

type OIDCHeaderBuilder struct {
	header map[string]interface{}
}

func NewOIDCHeaderBuilder(base map[string]interface{}) *OIDCHeaderBuilder {
	b := &OIDCHeaderBuilder{base}
	return b
}

func (b *OIDCHeaderBuilder) KeyID(keyID string) *OIDCHeaderBuilder {
	if keyID == "" {
		b.header[propKeyID] = nil
	} else {
		b.header[propKeyID] = keyID
	}
	return b
}

func (b *OIDCHeaderBuilder) Alg(alg string) *OIDCHeaderBuilder {
	if alg == "" {
		b.header[propAlg] = nil
	} else {
		b.header[propAlg] = alg
	}
	return b
}

func (b *OIDCHeaderBuilder) Build() map[string]interface{} {
	return b.header
}

type OIDCClaimsBuilder struct {
	claims OIDCClaims
}

func NewOIDCClaimsBuilder(base OIDCClaims) *OIDCClaimsBuilder {
	b := &OIDCClaimsBuilder{base}
	return b
}

func (b *OIDCClaimsBuilder) Build() OIDCClaims {
	return b.claims
}

func (b *OIDCClaimsBuilder) Audience(aud ...string) *OIDCClaimsBuilder {
	b.claims.Audience = aud
	return b
}

func (b *OIDCClaimsBuilder) ExpiresAt(expiresAt time.Time) *OIDCClaimsBuilder {
	b.claims.ExpiresAt = jwtgo.At(expiresAt)
	return b
}

func (b *OIDCClaimsBuilder) ID(id string) *OIDCClaimsBuilder {
	b.claims.ID = id
	return b
}

func (b *OIDCClaimsBuilder) IssuedAt(issuedAt time.Time) *OIDCClaimsBuilder {
	b.claims.IssuedAt = jwtgo.At(issuedAt)
	return b
}

func (b *OIDCClaimsBuilder) Issuer(issuer string) *OIDCClaimsBuilder {
	b.claims.Issuer = issuer
	return b
}

func (b *OIDCClaimsBuilder) NotBefore(notBefore time.Time) *OIDCClaimsBuilder {
	b.claims.NotBefore = jwtgo.At(notBefore)
	return b
}

func (b *OIDCClaimsBuilder) Subject(subject string) *OIDCClaimsBuilder {
	b.claims.Subject = subject
	return b
}

func (b *OIDCClaimsBuilder) UserUUID(userUUID string) *OIDCClaimsBuilder {
	b.claims.UserUUID = userUUID
	return b
}

func (b *OIDCClaimsBuilder) GivenName(givenName string) *OIDCClaimsBuilder {
	b.claims.GivenName = givenName
	return b
}

func (b *OIDCClaimsBuilder) FamilyName(familyName string) *OIDCClaimsBuilder {
	b.claims.FamilyName = familyName
	return b
}

func (b *OIDCClaimsBuilder) Email(email string) *OIDCClaimsBuilder {
	b.claims.Email = email
	return b
}

func (b *OIDCClaimsBuilder) ZoneID(zoneID string) *OIDCClaimsBuilder {
	b.claims.ZoneID = zoneID
	return b
}

func (b *OIDCClaimsBuilder) WithoutAudience() *OIDCClaimsBuilder {
	b.claims.Audience = nil
	return b
}

func (b *OIDCClaimsBuilder) WithoutExpiresAt() *OIDCClaimsBuilder {
	b.claims.ExpiresAt = nil
	return b
}

func (b *OIDCClaimsBuilder) WithoutIssuedAt() *OIDCClaimsBuilder {
	b.claims.IssuedAt = nil
	return b
}

func (b *OIDCClaimsBuilder) WithoutNotBefore() *OIDCClaimsBuilder {
	b.claims.NotBefore = nil
	return b
}
