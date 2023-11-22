// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sap/cloud-security-client-go/env"
	"github.com/sap/cloud-security-client-go/mocks"
	"github.com/stretchr/testify/assert"
)

func TestAdditionalDomain(t *testing.T) {
	oidcMockServer, err := mocks.NewOIDCMockServer()
	if err != nil {
		t.Errorf("error creating test setup: %v", err)
	}
	m := NewMiddleware(env.DefaultIdentity{
		ClientID:     oidcMockServer.Config.ClientID,
		ClientSecret: oidcMockServer.Config.ClientSecret,
		URL:          oidcMockServer.Config.URL,
		Domains:      append([]string{"my.primary.domain"}, oidcMockServer.Config.Domains...),
	}, Options{
		HTTPClient: oidcMockServer.Server.Client(),
	})

	rawToken, err := oidcMockServer.SignToken(oidcMockServer.DefaultClaims(), oidcMockServer.DefaultHeaders())
	if err != nil {
		t.Errorf("unable to sign provided test token: %v", err)
	}

	_, err = m.parseAndValidateJWT(rawToken)
	if err != nil {
		t.Error("unexpected error: ", err.Error())
	}
}

func TestAuthMiddleware_getOIDCTenant(t *testing.T) {
	oidcMockServer, err := mocks.NewOIDCMockServer()
	if err != nil {
		t.Errorf("error creating test setup: %v", err)
	}
	m := NewMiddleware(env.DefaultIdentity{
		ClientID:     oidcMockServer.Config.ClientID,
		ClientSecret: oidcMockServer.Config.ClientSecret,
		URL:          oidcMockServer.Config.URL,
		Domains:      oidcMockServer.Config.Domains,
	}, Options{
		HTTPClient: oidcMockServer.Server.Client(),
	})

	rawToken, err := oidcMockServer.SignToken(oidcMockServer.DefaultClaims(), oidcMockServer.DefaultHeaders())
	if err != nil {
		t.Errorf("unable to sign provided test token: %v", err)
	}

	token, err := m.parseAndValidateJWT(rawToken)
	if err != nil {
		t.Errorf("unable to parse provided test token: %v", err)
	}

	concurrentRuns := 5
	var wg sync.WaitGroup
	wg.Add(concurrentRuns)

	for i := 0; i < concurrentRuns; i++ {
		go func(i int) {
			defer wg.Done()

			set, err := m.getOIDCTenant(token.Issuer(), token.CustomIssuer())
			if err != nil || set == nil {
				t.Errorf("unexpected error on getOIDCTenant(), %v", err)
			}
			if set.ProviderJSON.Issuer != oidcMockServer.Server.URL {
				t.Errorf("GetOIDCTenant() in iteration %d; got = %s, want: %s", i, set.ProviderJSON.Issuer, oidcMockServer.Server.URL)
			} else {
				t.Logf("response %d as expected: %s", i, set.ProviderJSON.Issuer)
			}
		}(i)
	}

	waitTimeout(&wg, 5*time.Second)

	if hits := oidcMockServer.WellKnownHitCounter; hits != 1 {
		t.Errorf("GetOIDCTenant() /.well-known/openid-configuration endpoint called too often; got = %d, want: 1", hits)
	}
}

func TestVerifyIssuerLocal(t *testing.T) {
	m := NewMiddleware(env.DefaultIdentity{
		Domains: []string{"127.0.0.1:52421"},
	}, Options{})

	// trusted url
	_, err := m.verifyIssuer("https://127.0.0.1:52421")
	assert.NoError(t, err)
}

func TestVerifyIssuer(t *testing.T) {
	trustedDomain := "accounts400.ondemand.com"
	m := NewMiddleware(env.DefaultIdentity{
		Domains: []string{"accounts400.cloud.sap", trustedDomain},
	}, Options{})

	// exact domain
	host, err := m.verifyIssuer("https://" + trustedDomain)
	assert.NoError(t, err)
	assert.Equal(t, host, trustedDomain)
	// trusted url
	host, err = m.verifyIssuer("https://test." + trustedDomain)
	assert.NoError(t, err)
	assert.Equal(t, host, "test."+trustedDomain)
	// trusted domain
	host, err = m.verifyIssuer("test." + trustedDomain)
	assert.NoError(t, err)
	assert.Equal(t, host, "test."+trustedDomain)

	// support domains with 1 - 63 characters only
	_, err = m.verifyIssuer(strings.Repeat("a", 1) + "." + trustedDomain)
	assert.NoError(t, err)
	_, err = m.verifyIssuer(strings.Repeat("a", 63) + "." + trustedDomain)
	assert.NoError(t, err)
	_, err = m.verifyIssuer(strings.Repeat("a", 64) + "." + trustedDomain)
	assert.Error(t, err)

	// error when issuer contains tabs or new lines
	_, err = m.verifyIssuer("te\tnant." + trustedDomain)
	assert.Error(t, err)
	_, err = m.verifyIssuer("tenant.accounts400.ond\temand.com")
	assert.Error(t, err)
	_, err = m.verifyIssuer("te\nnant." + trustedDomain)
	assert.Error(t, err)
	_, err = m.verifyIssuer("tenant.accounts400.ond\nemand.com")
	assert.Error(t, err)

	// error when issuer contains encoded characters
	_, err = m.verifyIssuer("https://tenant%2e" + trustedDomain) // %2e instead of .
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://tenant%2d0815.accounts400.ond\nemand.com")
	assert.Error(t, err)

	// empty issuer
	_, err = m.verifyIssuer("")
	assert.Error(t, err)
	// illegal subdomain
	_, err = m.verifyIssuer("https://my-" + trustedDomain)
	assert.Error(t, err)

	// invalid url
	_, err = m.verifyIssuer("https://")
	assert.Error(t, err)

	// error if http protocol is used
	_, err = m.verifyIssuer("http://" + trustedDomain)
	assert.Error(t, err)

	// error when issuer contains more than a valid subdomain of the trusted domains
	_, err = m.verifyIssuer("https://" + trustedDomain + "a")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "%2f")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "%2fpath")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "&")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "%26")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "?")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "?foo")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + trustedDomain + "#")
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + "user@" + trustedDomain)
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + "user%40" + trustedDomain)
	assert.Error(t, err)
	_, err = m.verifyIssuer("https://" + "tenant!" + trustedDomain)
	assert.Error(t, err)
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
