// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"github.com/sap/cloud-security-client-go/env"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"

	"github.com/sap/cloud-security-client-go/mocks"
)

func TestEnd2End(t *testing.T) {
	testServer, oidcMockServer := GetTestServer("")
	client := testServer.Client()
	defer testServer.Close()
	defer oidcMockServer.Server.Close()

	customDomainTestServer, customDomainOidcMockServer := GetTestServer("https://custom.oidc-server.com/")
	customDomainClient := customDomainTestServer.Client()
	defer customDomainTestServer.Close()
	defer customDomainOidcMockServer.Server.Close()

	tests := []struct {
		name                string
		header              map[string]interface{}
		claims              mocks.OIDCClaims
		optCustomDomainTest bool
		wantErr             bool
	}{
		{
			name:    "valid",
			header:  oidcMockServer.DefaultHeaders(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
		}, {
			name:   "valid with aud array",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient", oidcMockServer.Config.ClientID).
				Build(),
			wantErr: false,
		},
		{
			name:   "valid with single aud",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience(oidcMockServer.Config.ClientID).
				Build(),
			wantErr: false,
		},
		{
			name: "no key id in token",
			header: mocks.NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				KeyID("").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: false,
		}, {
			name:   "expired",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ExpiresAt(time.Now().Add(-1 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name:   "no expiry provided",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				WithoutExpiresAt().
				Build(),
			wantErr: true,
		}, {
			name:   "before validity",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				NotBefore(time.Now().Add(1 * time.Minute)).
				Build(),
			wantErr: true,
		}, {
			name:   "wrong audience",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient").
				Build(),
			wantErr: true,
		}, {
			name:   "wrong audience array",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Audience("notMyClient", "neitherThisOne").
				Build(),
			wantErr: true,
		}, {
			name:   "wrong issuer",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("https://another.oidc-server.com/").
				Build(),
			wantErr: true,
		}, {
			name:   "custom issuer",
			header: customDomainOidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(customDomainOidcMockServer.DefaultClaims()).
				Issuer("https://custom.oidc-server.com/").
				IasIssuer(customDomainOidcMockServer.Server.URL).
				Build(),
			optCustomDomainTest: true,
			wantErr:             false,
		}, {
			name:   "no http/s prefix for issuer",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("127.0.0.1:64004").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer(oidcMockServer.Server.URL + "?redirect=https://malicious.ondemand.com/tokens%3Ftenant=9451dd2etrial").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious2",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer(oidcMockServer.Server.URL + "\\\\@malicious.ondemand.com").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious3",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer(oidcMockServer.Server.URL + "@malicious.ondemand.com").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious4",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("https://malicious.ondemand.com/token_keys///" + oidcMockServer.Server.URL).
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious5",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("https://malicious.ondemand.com/token_keys@" + strings.TrimPrefix(oidcMockServer.Server.URL, "https://")).
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious6",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer(oidcMockServer.Server.URL + "///malicious.ondemand.com/token_keys").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer malicious7",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer(oidcMockServer.Server.URL + "\\\\@malicious.ondemand.com/token_keys").
				Build(),
			wantErr: true,
		}, {
			name:   "issuer empty",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				Issuer("").
				Build(),
			wantErr: true,
		}, {
			name: "wrong key id",
			header: mocks.NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				KeyID("wrongKey").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name: "none algorithm",
			header: mocks.NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				Alg(jwa.NoSignature).
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name: "empty algorithm",
			header: mocks.NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				Alg("").
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name: "wrong algorithm",
			header: mocks.NewOIDCHeaderBuilder(oidcMockServer.DefaultHeaders()).
				Alg(jwa.HS256).
				Build(),
			claims:  oidcMockServer.DefaultClaims(),
			wantErr: true,
		}, {
			name:   "jwks rejects zone",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ZoneID(mocks.InvalidZoneID).
				Build(),
			wantErr: true,
		}, {
			name:   "lib rejects unaccepted zone again",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ZoneID(mocks.InvalidZoneID).
				Build(),
			wantErr: true,
		}, {
			name:   "lib accepts any zone",
			header: oidcMockServer.DefaultHeaders(),
			claims: mocks.NewOIDCClaimsBuilder(oidcMockServer.DefaultClaims()).
				ZoneID(uuid.New().String()).
				Build(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s, ts, c := oidcMockServer, testServer, client
			if tt.optCustomDomainTest {
				s = customDomainOidcMockServer
				ts = customDomainTestServer
				c = customDomainClient
			}

			timeout, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelFunc()
			req, _ := http.NewRequestWithContext(timeout, http.MethodGet, ts.URL+"/helloWorld", http.NoBody)
			authHeader, err := s.SignToken(tt.claims, tt.header)
			if err != nil {
				t.Errorf("unable to sign provided test token: %v", err)
			}
			req.Header.Add("Authorization", "Bearer "+authHeader)
			response, err := c.Do(req)
			if err != nil {
				t.Errorf("unexpected error during request: %v", err)
			}
			defer response.Body.Close()

			if tt.wantErr == false {
				if response.StatusCode != 200 {
					t.Errorf("req to test server failed: expected: 200, got: %d", response.StatusCode)
				}
			} else {
				if response.StatusCode != 401 {
					t.Errorf("req to test server succeeded unexpectedly: expected: 401, got: %d", response.StatusCode)
				}
			}
			body, _ := io.ReadAll(response.Body)
			t.Log(string(body))
		})
	}
}

func GetTestHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		cert := ClientCertificateFromCtx(req)
		if cert != nil {
			_, _ = rw.Write([]byte("entered test handler using cert: " + string(cert.x509Cert.Raw)))
		}
		_, _ = rw.Write([]byte("entered test handler"))
	}
}

func GetTestServer(customIssuer string) (clientServer *httptest.Server, oidcServer *mocks.MockServer) {
	mockServer, _ := mocks.NewOIDCMockServerWithCustomIssuer(customIssuer)
	options := Options{
		ErrorHandler: nil,
		HTTPClient:   mockServer.Server.Client(),
	}
	middleware := NewMiddleware(mockServer.Config, options)
	server := httptest.NewTLSServer(middleware.AuthenticationHandler(GetTestHandler()))

	return server, mockServer
}

func TestGetTokenFlows_sameInstance(t *testing.T) {
	middleware := NewMiddleware(&env.DefaultIdentity{
		ClientID:     "09932670-9440-445d-be3e-432a97d7e2ef",
		ClientSecret: "[the_CLIENT.secret:3[/abc",
		URL:          "https://mySaaS.accounts400.ondemand.com",
	}, Options{})
	tokenFlows, err := middleware.GetTokenFlows()
	assert.NoError(t, err)
	assert.NotNil(t, tokenFlows)

	sameTokenFlows, err := middleware.GetTokenFlows()
	assert.NoError(t, err)
	assert.Same(t, tokenFlows, sameTokenFlows)
}
