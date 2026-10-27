// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import "net/http"

func discoveryClient(client *http.Client) (discovery *http.Client, closeIdleConnections func()) {
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	tlsTransport, ok := transport.(*http.Transport)
	if !ok {
		// Custom transports own their TLS authentication and must keep discovery credential-free.
		return client, func() {}
	}
	clientCopy := *client
	clonedTransport := tlsTransport.Clone()
	if clonedTransport.TLSClientConfig != nil {
		clonedTransport.TLSClientConfig = clonedTransport.TLSClientConfig.Clone()
		clonedTransport.TLSClientConfig.Certificates = nil
		clonedTransport.TLSClientConfig.GetClientCertificate = nil
		// Resumed sessions can retain authentication from a previous token request.
		clonedTransport.TLSClientConfig.ClientSessionCache = nil
	}
	clientCopy.Transport = clonedTransport
	return &clientCopy, clonedTransport.CloseIdleConnections
}
