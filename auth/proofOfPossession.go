// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package auth

// validateCertificate checks proof of possession in addition to audience validation
// to make sure that it was called by a trust-worthy consumer.
// Trust between application and applications/services is established with certificates in principle.
// Proof of possession uses certificates as proof token and therefore, x.509 based mTLS communication is demanded.
import (
	"errors"
	"fmt"
)

var ErrNoClientCert = errors.New("there is no x509 client certificate provided")

// validateCertificate runs all proof of possession checks.
// This ensures that the token was issued for the sender.
func validateCertificate(clientCertificate *Certificate, token Token) error {
	if clientCertificate == nil {
		return ErrNoClientCert
	}
	return validateX5tThumbprint(clientCertificate, token)
}

// validateX5tThumbprint compares the thumbprint of the provided X509 client certificate against the cnf claim with the confirmation method "x5t#S256".
// This ensures that the token was issued for the sender.
func validateX5tThumbprint(clientCertificate *Certificate, token Token) error {
	if clientCertificate == nil {
		return ErrNoClientCert
	}

	cnfThumbprint := token.getCnfClaimMember(claimCnfMemberX5t)
	if cnfThumbprint == "" {
		return fmt.Errorf("token provides no cnf member for thumbprint confirmation")
	}

	if cnfThumbprint != clientCertificate.GetThumbprint() {
		return fmt.Errorf("token thumbprint confirmation failed")
	}
	return nil
}
