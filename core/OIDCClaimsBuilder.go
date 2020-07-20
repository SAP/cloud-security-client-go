// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"time"
)

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

func (b *OIDCClaimsBuilder) ID(ID string) *OIDCClaimsBuilder {
	b.claims.ID = ID
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

func (b *OIDCClaimsBuilder) UserName(userName string) *OIDCClaimsBuilder {
	b.claims.UserName = userName
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

func (b *OIDCClaimsBuilder) ZoneId(zoneId string) *OIDCClaimsBuilder {
	b.claims.ZoneId = zoneId
	return b
}
