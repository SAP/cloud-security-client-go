// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

// parseAndValidateCertificate checks proof of possession in addition to audience validation
// to make sure that it was called by a trust-worthy consumer.
// Trust between application and applications/services is established with certificates in principle.
// Proof of possession uses certificates as proof token and therefore, x.509 based mTLS communication is demanded.
import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

var ErrNoClientCert = errors.New("there is no x509 client certificate provided")
var ErrNoToken = errors.New("there is no token provided")

func parseAndValidateCertificate(clientCertificate *x509.Certificate, token Token) error {
	if clientCertificate == nil {
		return ErrNoClientCert
	}
	if token == nil {
		return ErrNoToken
	}
	return ValidateX5tThumbprint(clientCertificate, token)
}

// ValidateX5tThumbprint compares the thumbprint of the provided X509 client certificate against the cnf claim with the confirmation method "x5t#S256".
// This ensures that the token was issued for the sender.
func ValidateX5tThumbprint(clientCertificate *x509.Certificate, token Token) error {
	if clientCertificate == nil {
		return ErrNoClientCert
	}
	if token == nil {
		return ErrNoToken
	}

	cnfThumbprint := token.getCnfClaimMember(claimCnfMemberX5t)
	if cnfThumbprint == "" {
		return fmt.Errorf("token provides no cnf member for thumbprint confirmation")
	}

	certThumbprintBytes := sha256.Sum256(clientCertificate.Raw)
	certThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(certThumbprintBytes[:])

	if cnfThumbprint != certThumbprint {
		return fmt.Errorf("token thumbprint confirmation failed")
	}
	return nil
}

// parseCertificate parses the X509 client certificate which is provided via the "x-forwarded-client-cert".
// It supports DER encoded and PEM encoded certificates.
// Returns nil, if certString is empty string.
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
