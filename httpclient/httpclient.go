// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0
package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sap/cloud-security-client-go/env"
)

const UserAgent = "go-sec-lib"

// DefaultTLSConfig creates default tls.Config. Initializes SystemCertPool with cert/key from identity config.
//
// identity provides certificate and key
func DefaultTLSConfig(identity env.Identity) (*tls.Config, error) {
	if !identity.IsCertificateBased() {
		return &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateOnceAsClient,
		}, nil
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
		return nil, errors.New("error adding certs to pool for DefaultTLSConfig")
	}
	tlsConfig := &tls.Config{
		MinVersion:    tls.VersionTLS12,
		RootCAs:       tlsCertPool,
		Certificates:  []tls.Certificate{tlsCert},
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	return tlsConfig, nil
}

// DefaultHTTPClient
//
// tlsConfig required in case of cert-based identity config
func DefaultHTTPClient(tlsConfig *tls.Config) *http.Client {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
			MaxIdleConns:    50,
		}
	}
	return client
}

// NewRequestWithUserAgent creates a request and sets the libs custom user agent
// it would be nicer to set this in the default http.client, but
// it's discouraged to manipulate the request in RoundTrip per official documentation
func NewRequestWithUserAgent(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("User-Agent", UserAgent)
	return r, nil
}
