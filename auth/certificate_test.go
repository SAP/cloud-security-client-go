// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	_ "embed"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed testdata/x-forwarded-client-cert.txt
var derCertFromFile string

func TestCertificate(t *testing.T) {
	t.Run("newCertificate() returns nil when no certificate is given", func(t *testing.T) {
		cert, err := newCertificate("")
		assert.Nil(t, cert)
		assert.Nil(t, err)
	})

	t.Run("newCertificate() fails when DER certificate is corrupt", func(t *testing.T) {
		cert, err := newCertificate("abc123")
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "cannot base64 decode certificate header:")
	})

	t.Run("newCertificate() fails when PEM certificate is corrupt", func(t *testing.T) {
		cert, err := newCertificate("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQxVENDQXIyZ0F3SUJBZ0lNSUxvRXNuTFFCdQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t")
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "cannot decode PEM formatted certificate header:")
	})

	t.Run("GetThumbprint() for PEM formatted cert", func(t *testing.T) {
		cert, _ := newCertificate(convertToPEM(t, derCertFromFile))
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
	})

	t.Run("GetThumbprint() for DER formatted cert", func(t *testing.T) {
		cert, _ := newCertificate(derCertFromFile)
		assert.Equal(t, "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM", cert.GetThumbprint())
	})
}
