// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchesTrustedDomain(t *testing.T) {
	tests := []struct {
		host    string
		domains []string
		matches bool
	}{
		{"accounts.example.com", []string{"accounts.example.com"}, true},
		{"tenant.accounts.example.com", []string{"accounts.example.com"}, true},
		{strings.Repeat("a", 63) + ".accounts.example.com", []string{"accounts.example.com"}, true},
		{strings.Repeat("a", 64) + ".accounts.example.com", []string{"accounts.example.com"}, false},
		{"tenant-name.accounts.example.com", []string{"accounts.example.com"}, true},
		{"tenant_name.accounts.example.com", []string{"accounts.example.com"}, false},
		{"evilaccounts.example.com", []string{"accounts.example.com"}, false},
		{"deep.tenant.accounts.example.com", []string{"accounts.example.com"}, false},
		{"accounts.example.com.attacker.example", []string{"accounts.example.com"}, false},
		{"attacker@accounts.example.com", []string{"accounts.example.com"}, false},
		{"tenant.accounts.example.com/", []string{"accounts.example.com"}, false},
		{"tenant.accounts.example.com", nil, false},
		{"tenant.accounts.example.com:443", []string{"accounts.example.com"}, false},
		{"tenant.accounts.example.com:443", []string{"accounts.example.com:443"}, true},
		{"tenant.accounts.example.com:8443", []string{"accounts.example.com:443"}, false},
		{"tenant.accounts.example.com", []string{"other.example", "accounts.example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			matches, err := Matches(tt.host, tt.domains)
			assert.NoError(t, err)
			assert.Equal(t, tt.matches, matches)
		})
	}
}
