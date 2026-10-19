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
	"net/url"
	"strings"
)

const pemCertificateType = "CERTIFICATE"

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

func (c *Certificate) normalizedPEM() string {
	pemCertificate := pem.EncodeToMemory(&pem.Block{Type: pemCertificateType, Bytes: c.x509Cert.Raw})
	return strings.NewReplacer("\\n", "", "\n", "").Replace(string(pemCertificate))
}

func parseCertificate(certString string) (*x509.Certificate, error) {
	if certString == "" {
		return nil, nil
	}

	certificate := extractCertificateFromForwardedHeader(certString)
	certificate = strings.ReplaceAll(certificate, "\\n", "\n")
	decoded, err := decodeCertificate(certificate)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func decodeCertificate(certificate string) ([]byte, error) {
	if pemBlock, _ := pem.Decode([]byte(certificate)); pemBlock != nil {
		return pemBlock.Bytes, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		return nil, fmt.Errorf("cannot base64 decode certificate header: %w", err)
	}
	if bytes.HasPrefix(decoded, []byte("-----BEGIN")) {
		pemBlock, _ := pem.Decode(decoded)
		if pemBlock == nil {
			return nil, fmt.Errorf("cannot decode PEM formatted certificate header: malformed PEM")
		}
		return pemBlock.Bytes, nil
	}
	return decoded, nil
}

func extractCertificateFromForwardedHeader(header string) string {
	if !strings.Contains(strings.ToLower(header), "hash=") {
		return header
	}

	entries := splitHeaderValue(header, ',')
	if len(entries) == 0 {
		return header
	}
	for _, field := range splitHeaderValue(entries[len(entries)-1], ';') {
		name, value, found := strings.Cut(field, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "cert") {
			continue
		}
		certificate := strings.Trim(strings.TrimSpace(value), "\"'")
		certificate = strings.ReplaceAll(certificate, `\"`, `"`)
		if decoded, err := url.PathUnescape(certificate); err == nil {
			return decoded
		}
		return certificate
	}
	return header
}

func splitHeaderValue(value string, delimiter rune) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for index, character := range value {
		if character == '"' && !isEscaped(value, index) {
			inQuotes = !inQuotes
		}
		if character == delimiter && !inQuotes {
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteRune(character)
	}
	if current.Len() > 0 {
		parts = append(parts, strings.TrimSpace(current.String()))
	}
	return parts
}

func isEscaped(value string, index int) bool {
	backslashCount := 0
	for index--; index >= 0 && value[index] == '\\'; index-- {
		backslashCount++
	}
	return backslashCount%2 == 1
}
