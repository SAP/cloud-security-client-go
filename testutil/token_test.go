// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenFromClaims(t *testing.T) {
	userUUID := uuid.NewString()
	m := map[string]interface{}{"user_uuid": userUUID}
	token, err := NewTokenFromClaims(m)
	assert.NoError(t, err)

	assert.Equal(t, userUUID, token.UserUUID(), "UserUUID() got = %v, want %v", token.UserUUID(), userUUID)
}
