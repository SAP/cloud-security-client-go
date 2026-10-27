// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package domain provides shared host/domain matching used to ensure that a
// host belongs to one of the identity service's trusted domains.
package domain

import (
	"regexp"
	"strings"
)

// Matches reports whether hostname belongs to one of the trusted domains,
// either as an exact match or as a direct subdomain.
func Matches(hostname string, domains []string) (bool, error) {
	for _, domain := range domains {
		if !strings.HasSuffix(hostname, domain) {
			continue
		}
		// hostname matches exactly trusted domain
		if hostname == domain {
			return true, nil
		}
		isValid, regexErr := isValidSubDomain(hostname, domain)
		if regexErr != nil {
			return false, regexErr
		}
		if isValid {
			return true, nil
		}
	}
	return false, nil
}

// isValidSubDomain additionally checks the subdomain because "my-accounts400.ondemand.com"
// does match the suffix of "accounts400.ondemand.com" but should not be allowed.
// It also returns false if hostname contains paths like /foo or ?test=true.
func isValidSubDomain(hostname, domain string) (bool, error) {
	validSubdomainPattern := "^[a-zA-Z0-9-]{1,63}\\." + regexp.QuoteMeta(domain) + "$"
	return regexp.MatchString(validSubdomainPattern, hostname)
}
