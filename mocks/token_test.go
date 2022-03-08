package mocks

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenFromClaims(t *testing.T) {
	userUUID := uuid.NewString()
	m := map[string]interface{}{"user_uuid": userUUID}
	claims, err := NewTokenFromClaims(m)
	assert.NoError(t, err)

	assert.Equal(t, userUUID, claims.UserUUID(), "UserUUID() got = %v, want %v", claims.UserUUID(), userUUID)
}
