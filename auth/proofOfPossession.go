// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

// validateCertificate checks proof of possession in addition to audience validation
// to make sure that it was called by a trust-worthy consumer.
// Trust between application and applications/services is established with certificates in principle.
// Proof of possession uses certificates as proof token and therefore, x.509 based mTLS communication is demanded.
import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrNoClientCert = errors.New("there is no x509 client certificate provided")
var ErrNoToken = errors.New("there is no token provided")

// validateCertificate runs all proof of possession checks.
// This ensures that the token was issued for the sender.
func validateCertificate(clientCertificate *Certificate, token Token) error {
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
func ValidateX5tThumbprint(clientCertificate *Certificate, token Token) error {
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

	certThumbprintBytes := sha256.Sum256(clientCertificate.x509Cert.Raw)
	certThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(certThumbprintBytes[:])

	if cnfThumbprint != certThumbprint {
		return fmt.Errorf("token thumbprint confirmation failed")
	}
	return nil
}
