// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/sap/cloud-security-client-go/testutil"
)

func TestNewTokenFromClaims(t *testing.T) {
	userUUID := uuid.NewString()
	m := map[string]interface{}{"user_uuid": userUUID}
	claims, err := testutil.NewTokenFromClaims(m)
	assert.NoError(t, err)

	assert.Equal(t, userUUID, claims.UserUUID(), "UserUUID() got = %v, want %v", claims.UserUUID(), userUUID)
}
