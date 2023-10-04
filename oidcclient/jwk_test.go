// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwk"
)

const jwksJSONString = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"default-kid-ias\",\"e\":\"AQAB\",\"use\":\"sig\",\"n\":\"AJtUGmczI7RHx3Ypqxz9_9mK_tc-vOXojlJcMm0VRvYvMLIDlIfj1BrkC_IYLpS2Vl1OTG8AS0xAgBDEG3EUzVU6JZKuIuuxD-iXrBySBQA2ytTYtCrjHD7osji7wyogxDJ2BtVz9191gjX7AlU_WKFPpViK2a_2bCL0K4vI3M6-EZMp20wbD2gDsoD1JYqag66WnTDtZqJjQm3mv6Ohj59_C8RMOtPSLX4AxoS-n_8lYneaRc2UFm_vZepgricMNIZ4TuoLekb_fDlg7cvRtH61gD8hH7iFvQfpkf9rxoclPSG21qbxV4svUVW27DOd_Ewo3eSRdnSb8ctuGnXQuKE=\"}]}"

func TestProviderJSON_assertMandatoryFieldsPresent(t *testing.T) {
	type fields struct {
		Issuer  string
		JWKsURL string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "all present",
			fields: fields{
				Issuer:  "https://mytenant.accounts400.ondemand.com",
				JWKsURL: "https://mytenant.accounts400.ondemand.com/oauth2/certs",
			},
			wantErr: false,
		}, {
			name: "issuer missing",
			fields: fields{
				JWKsURL: "https://mytenant.accounts400.ondemand.com/oauth2/certs",
			},
			wantErr: true,
		}, {
			name: "jwks missing",
			fields: fields{
				Issuer: "https://mytenant.accounts400.ondemand.com",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ProviderJSON{
				Issuer:  tt.fields.Issuer,
				JWKsURL: tt.fields.JWKsURL,
			}
			if err := p.assertMandatoryFieldsPresent(); (err != nil) != tt.wantErr {
				t.Errorf("assertMandatoryFieldsPresent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDCTenant_ReadJWKs(t *testing.T) {
	type fields struct {
		Duration         time.Duration
		Tenant           TenantInfo
		ExpectedErrorMsg string
	}
	tests := []struct {
		name             string
		fields           fields
		wantErr          bool
		wantProviderJSON bool
	}{
		{
			name: "read from cache with accepted tenant credentials",
			fields: fields{
				Duration: 2 * time.Second,
				Tenant:   TenantInfo{"client-id", "app-tid", "azp"},
			},
			wantErr:          false,
			wantProviderJSON: false,
		}, {
			name: "read from cache with unknown tenant credentials",
			fields: fields{
				Duration: 2 * time.Second,
				Tenant:   TenantInfo{"unknown-client-id", "unknown-app-tid", "unknown-azp"},
				ExpectedErrorMsg: "tenant credentials: {ClientID:unknown-client-id AppTID:unknown-app-tid Azp:unknown-azp} " +
					"are not accepted by the identity service",
			},
			wantErr:          true,
			wantProviderJSON: false,
		},
		{
			name: "read from token keys endpoint with accepted tenant credentials",
			fields: fields{
				Duration: 0,
				Tenant:   TenantInfo{"client-id", "app-tid", "azp"},
			},
			wantErr:          false,
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with denied tenant credentials",
			fields: fields{
				Duration: 0,
				Tenant:   TenantInfo{"unknown-client-id", "unknown-app-tid", "unknown-azp"},
				ExpectedErrorMsg: "error updating JWKs: failed to fetch jwks from remote " +
					"for tenant credentials {ClientID:unknown-client-id AppTID:unknown-app-tid Azp:unknown-azp}",
			},
			wantErr:          true,
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with accepted tenant credentials provoking parsing error",
			fields: fields{
				Duration:         0,
				Tenant:           TenantInfo{ClientID: "provide-invalidJWKS"},
				ExpectedErrorMsg: "error updating JWKs: failed to parse JWK set: failed to unmarshal JWK set",
			},
			wantErr:          true, // as jwks endpoint returns no JSON
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with deleted tenant credentials",
			fields: fields{
				Duration: 0,
				Tenant:   TenantInfo{"deleted-client-id", "deleted-app-tid", "deleted-azp"},
				ExpectedErrorMsg: "error updating JWKs: failed to fetch jwks from remote for " +
					"tenant credentials {ClientID:deleted-client-id AppTID:deleted-app-tid Azp:deleted-azp}",
			},
			wantErr:          true,
			wantProviderJSON: true,
		},
	}

	router := NewRouter()
	localServer := httptest.NewServer(router)
	defer localServer.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var providerJSON ProviderJSON
			if tt.wantProviderJSON {
				localServerURL, _ := url.Parse(localServer.URL)
				providerJSON.JWKsURL = fmt.Sprintf("%s/oauth2/certs", localServerURL)
			}
			jwksJSON, _ := jwk.ParseString(jwksJSONString)
			tenant := OIDCTenant{
				jwksExpiry: time.Now().Add(tt.fields.Duration),
				acceptedTenants: map[TenantInfo]bool{
					{ClientID: "client-id", AppTID: "app-tid", Azp: "azp"}:                         true,
					{ClientID: "deleted-client-id", AppTID: "deleted-app-tid", Azp: "deleted-azp"}: true,
					{ClientID: "unknown-client-id", AppTID: "unknown-app-tid", Azp: "unknown-azp"}: false,
				},
				httpClient:   http.DefaultClient,
				jwks:         jwksJSON,
				ProviderJSON: providerJSON,
			}
			jwks, err := tenant.GetJWKs(tt.fields.Tenant)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetJWKs() does not provide error = %v, tenantCredentials %+v", err, tt.fields.Tenant)
				}
				if !strings.HasPrefix(err.Error(), tt.fields.ExpectedErrorMsg) {
					t.Errorf("GetJWKs() does not provide expected error message = %v", err.Error())
				}
			} else if jwks == nil {
				t.Errorf("GetJWKs() returns nil = %v, tenantCredentials %+v", err, tt.fields.Tenant)
			}
		})
	}
}

func NewRouter() (r *mux.Router) {
	r = mux.NewRouter()
	r.HandleFunc("/oauth2/certs", ReturnJWKS).Methods(http.MethodGet).Headers(clientIDHeader, "client-id", appTIDHeader, "app-tid", azpHeader, "azp")
	r.HandleFunc("/oauth2/certs", ReturnInvalidHeaders).Methods(http.MethodGet).Headers(clientIDHeader, "unknown-client-id", appTIDHeader, "unknown-app-tid", azpHeader, "unknown-azp")
	r.HandleFunc("/oauth2/certs", ReturnInvalidHeaders).Methods(http.MethodGet).Headers(clientIDHeader, "deleted-client-id", appTIDHeader, "deleted-app-tid", azpHeader, "deleted-azp")
	r.HandleFunc("/oauth2/certs", ReturnInvalidJWKS).Methods(http.MethodGet).Headers(clientIDHeader, "provide-invalidJWKS")
	return r
}

func ReturnJWKS(writer http.ResponseWriter, _ *http.Request) {
	_, _ = writer.Write([]byte(jwksJSONString))
}

func ReturnInvalidJWKS(writer http.ResponseWriter, _ *http.Request) {
	_, _ = writer.Write([]byte("\"kid\":\"default-kid-ias\""))
}

func ReturnInvalidHeaders(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(400)
}
