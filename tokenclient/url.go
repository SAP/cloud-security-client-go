// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sap/cloud-security-client-go/internal/domain"
)

func (t *TokenFlows) getURL(customerTenantURL string, options RequestOptions) (string, error) {
	tenantURL, err := t.tenantURL(customerTenantURL)
	if err != nil {
		return "", err
	}
	endpoint := options.TokenEndpoint
	if endpoint == "" {
		endpoint = tokenEndpoint
	}
	path, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("token endpoint path can't be parsed: %w", err)
	}
	if !strings.HasPrefix(path.Path, "/") || strings.HasPrefix(path.Path, "//") ||
		path.IsAbs() || path.Host != "" || path.User != nil ||
		strings.ContainsAny(endpoint, "@\\?#") || strings.ContainsAny(path.Path, "@\\?#") {
		return "", fmt.Errorf("token endpoint must be an absolute path without authority, user information, query or fragment")
	}
	tenantURL.Path = path.Path
	tenantURL.RawPath = path.RawPath
	return tenantURL.String(), nil
}

func (t *TokenFlows) tenantURL(value string) (*url.URL, error) {
	u, err := t.trustedURL(value, "customer tenant url")
	if err != nil {
		return nil, err
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return nil, fmt.Errorf("customer tenant url '%v' is not a valid url: must not contain a path", value)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, fmt.Errorf("customer tenant url '%v' is not a valid url: must not contain a query", value)
	}
	return u, nil
}

func (t *TokenFlows) trustedURL(value, name string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%s '%v' can't be parsed: %w", name, value, err)
	}
	if u.Scheme != "https" || u.Opaque != "" {
		return nil, fmt.Errorf("%s '%v' is not a valid url: scheme must be https", name, value)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s '%v' is not a valid url: must not contain user information", name, value)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%s '%v' is not a valid url: missing host", name, value)
	}
	if strings.Contains(value, "#") {
		return nil, fmt.Errorf("%s '%v' is not a valid url: must not contain a fragment", name, value)
	}
	matches, err := domain.Matches(u.Host, t.identity.GetDomains())
	if err != nil {
		return nil, fmt.Errorf("error matching domain: %w", err)
	}
	if !matches {
		return nil, fmt.Errorf("%s '%v' does not match any of the trusted domains", name, value)
	}
	return u, nil
}
