// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package httpclient

import (
	_ "embed"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/stretchr/testify/assert"
	"runtime"
	"testing"
)

//go:embed testdata/certificate.pem
var certificate string

//go:embed testdata/privateKey.pem
var key string

//go:embed testdata/privateRSAKey.pem
var otherKey string

var mTLSConfig = env.Identity{
	ClientID:    "09932670-9440-445d-be3e-432a97d7e2ef",
	Certificate: certificate,
	Key:         key,
	URL:         "https://mySaaS.accounts400.ondemand.com",
}

func TestDefaultHTTPClient_ClientCertificate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip test on windows os. Module crypto/x509 supports SystemCertPool with go 1.18 (https://go-review.googlesource.com/c/go/+/353589/)")
	}
	tlsConfig, err := DefaultTLSConfig(mTLSConfig)
	assert.NoError(t, err)
	httpsClient := DefaultHTTPClient(tlsConfig)
	assert.NotNil(t, httpsClient)
}

func TestDefaultHTTPClient_ClientCredentials(t *testing.T) {
	httpsClient := DefaultHTTPClient(nil)
	assert.NotNil(t, httpsClient)
}

func TestDefaultTLSConfig_shouldFailIfKeyDoesNotMatch(t *testing.T) {
	mTLSConfig.Certificate = otherKey
	tlsConfig, err := DefaultTLSConfig(mTLSConfig)
	assert.Error(t, err)
	assert.Nil(t, tlsConfig)
}
