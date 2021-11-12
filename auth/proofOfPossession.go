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
	"fmt"
)

func parseAndValidateCertificate(clientCertificate string, token Token) error {
	if clientCertificate == "" {
		return fmt.Errorf("there is no client certificate provided")
	}
	if token == nil {
		return fmt.Errorf("there is no token provided")
	}

	x509ClientCert, err := ParseCertHeader(clientCertificate)
	if err != nil {
		return fmt.Errorf("cannot parse client certificate: %v", err)
	}
	return ValidateX5tThumbprint(x509ClientCert, token)
}

// In order to check whether the token was issued for the sender,
// the cnf token claim with the confirmation method “x5t#S256” needs to be compared with the thumbprint of the
// provided X509 client certificate.
// See also RFC 8705
func ValidateX5tThumbprint(clientCertificate *x509.Certificate, token Token) error {
	if clientCertificate == nil {
		return fmt.Errorf("there is no x509 client certificate provided")
	}
	if token == nil {
		return fmt.Errorf("there is no token provided")
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

// Parses the X509 client certificate which is provided via the "x-forwarded-client-cert".
// It supports DER encoded and PEM encoded certificates.
func ParseCertHeader(certHeader string) (*x509.Certificate, error) {
	if certHeader == "" {
		return nil, fmt.Errorf("there is no certificate header provided")
	}
	const PEMIndicator string = "-----BEGIN"
	decoded, err := base64.StdEncoding.DecodeString(certHeader)
	if err != nil {
		return nil, fmt.Errorf("cannot base64 decode certificate header: %w", err)
	}
	if bytes.HasPrefix(decoded, []byte(PEMIndicator)) { // in case of apache proxy
		pemBlock, _ := pem.Decode(decoded)
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
