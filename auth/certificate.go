// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Certificate is the public API to access claims of the X509 client certificate.
type Certificate struct {
	x509Cert *x509.Certificate
}

// newCertificate parses the X509 client certificate string.
// It supports DER and PEM formatted certificates.
// Returns nil, if certString is empty string.
// Returns error in case of parsing error.
func newCertificate(certString string) (*Certificate, error) {
	x509Cert, err := parseCertificate(certString)
	if x509Cert != nil {
		return &Certificate{
			x509Cert: x509Cert,
		}, nil
	}
	return nil, err
}

// GetThumbprint returns the thumbprint without padding.
func (c *Certificate) GetThumbprint() string {
	thumbprintBytes := sha256.Sum256(c.x509Cert.Raw)
	thumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprintBytes[:])

	return thumbprint
}

func parseCertificate(certString string) (*x509.Certificate, error) {
	if certString == "" {
		return nil, nil
	}
	const PEMIndicator string = "-----BEGIN"
	decoded, err := base64.StdEncoding.DecodeString(certString)
	if err != nil {
		return nil, fmt.Errorf("cannot base64 decode certificate header: %w", err)
	}
	if bytes.HasPrefix(decoded, []byte(PEMIndicator)) { // in case of apache proxy
		pemBlock, err := pem.Decode(decoded)
		if pemBlock == nil {
			return nil, fmt.Errorf("cannot decode PEM formatted certificate header: %v", err)
		}
		decoded = pemBlock.Bytes
	}
	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
