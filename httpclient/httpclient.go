// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/sap/cloud-security-client-go/env"
	"net/http"
	"time"
)

// Default: SystemCertPool with cert/key from identity config.
func DefaultTLSConfig(identity env.Identity) (*tls.Config, error) {
	if !identity.IsCertificateBased() {
		return nil, fmt.Errorf("error creating DefaultTLSConfig, identity does not provide certificate/key")
	}
	certPEMBlock := []byte(identity.GetCertificate())
	keyPEMBlock := []byte(identity.GetKey())

	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 key pair for DefaultTLSConfig: %w", err)
	}
	tlsCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error setting up cert pool for DefaultTLSConfig: %w", err)
	}
	ok := tlsCertPool.AppendCertsFromPEM(certPEMBlock)
	if !ok {
		return nil, fmt.Errorf("error adding certs to pool for DefaultTLSConfig: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      tlsCertPool,
		Certificates: []tls.Certificate{tlsCert},
	}
	return tlsConfig, nil
}

// tlsConfig required in case of cert-based identity config
func DefaultHTTPClient(tlsConfig *tls.Config) *http.Client {
	client := &http.Client{
		Timeout: time.Second * 10, // TODO check
	}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConnsPerHost: 50, // TODO check
		}
	}
	return client
}
