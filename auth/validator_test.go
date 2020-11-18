// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"github.com/sap/cloud-security-client-go/env"
	"sync"
	"testing"
	"time"
)

func TestAuthMiddleware_getOIDCTenant(t *testing.T) {
	oidcMockServer, err := NewOIDCMockServer()
	if err != nil {
		t.Errorf("error creating test setup: %v", err)
	}
	m := NewMiddleware(env.IASConfig{
		ClientID:     oidcMockServer.Config.ClientID,
		ClientSecret: oidcMockServer.Config.ClientSecret,
		URL:          oidcMockServer.Config.URL,
		Domain:       oidcMockServer.Config.Domain,
	}, Options{
		HTTPClient: oidcMockServer.Server.Client(),
	})

	rawToken, err := oidcMockServer.SignToken(oidcMockServer.DefaultClaims(), oidcMockServer.DefaultHeaders())
	if err != nil {
		t.Errorf("unable to sign provided test token: %v", err)
	}

	token, _, err := m.parser.ParseUnverified(rawToken, new(OIDCClaims))
	if err != nil {
		t.Errorf("unable to parse provided test token: %v", err)
	}

	concurrentRuns := 5
	var wg sync.WaitGroup
	wg.Add(concurrentRuns)

	for i := 0; i < concurrentRuns; i++ {
		go func(i int) {
			defer wg.Done()

			set, err := m.getOIDCTenant(token)
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
	} else {
		t.Logf("GetOIDCTenant() /.well-known/openid-configuration endpoint called only once as expected")
	}
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
