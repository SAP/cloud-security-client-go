// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwk"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
		ZoneID           string
		ExpectedErrorMsg string
	}
	tests := []struct {
		name             string
		fields           fields
		wantErr          bool
		wantProviderJSON bool
	}{
		{
			name: "read from cache with accepted zone",
			fields: fields{
				Duration: 2 * time.Second,
				ZoneID:   "zone-id",
			},
			wantErr:          false,
			wantProviderJSON: false,
		}, {
			name: "read from cache with denied zone",
			fields: fields{
				Duration:         2 * time.Second,
				ZoneID:           "unknown-zone-id",
				ExpectedErrorMsg: "zone_uuid unknown-zone-id is not accepted by the identity service tenant",
			},
			wantErr:          true,
			wantProviderJSON: false,
		},
		{
			name: "read from token keys endpoint with accepted zone",
			fields: fields{
				Duration: 0,
				ZoneID:   "zone-id",
			},
			wantErr:          false,
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with denied zone",
			fields: fields{
				Duration:         0,
				ZoneID:           "unknown-zone-id",
				ExpectedErrorMsg: "error updating JWKs: failed to fetch jwks from remote for x-zone_uuid unknown-zone-id",
			},
			wantErr:          true,
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with accepted zone but no jwks response",
			fields: fields{
				Duration:         0,
				ZoneID:           "provide-invalidJWKS",
				ExpectedErrorMsg: "error updating JWKs: failed to fetch jwks from remote: ",
			},
			wantErr:          true, // as providerJSON is nil
			wantProviderJSON: false,
		}, {
			name: "read from token keys endpoint with accepted zone provoking parsing error",
			fields: fields{
				Duration:         0,
				ZoneID:           "provide-invalidJWKS",
				ExpectedErrorMsg: "error updating JWKs: failed to parse JWK set: failed to unmarshal JWK set",
			},
			wantErr:          true, // as jwks endpoint returns no JSON
			wantProviderJSON: true,
		}, {
			name: "read from token keys endpoint with deleted zone",
			fields: fields{
				Duration:         0,
				ZoneID:           "deleted-zone-id",
				ExpectedErrorMsg: "error updating JWKs: failed to fetch jwks from remote for x-zone_uuid deleted-zone-id",
			},
			wantErr:          true,
			wantProviderJSON: true,
		},
	}
	for _, tt := range tests {
		var providerJSON ProviderJSON
		if tt.wantProviderJSON {
			router := NewRouter()
			localServer := httptest.NewServer(router)
			defer localServer.Close()
			localServerURL, _ := url.Parse(localServer.URL)
			providerJSON.JWKsURL = fmt.Sprintf("%s/oauth2/certs", localServerURL)
		}
		t.Run(tt.name, func(t *testing.T) {
			jwksJSON, _ := jwk.ParseString(jwksJSONString)
			tenant := OIDCTenant{
				jwksExpiry:      time.Now().Add(tt.fields.Duration),
				acceptedZoneIds: map[string]bool{"zone-id": true, "deleted-zone-id": true, "unknown-zone-id": false},
				httpClient:      http.DefaultClient,
				jwks:            jwksJSON,
				ProviderJSON:    providerJSON,
			}
			jwks, err := tenant.GetJWKs(tt.fields.ZoneID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetJWKs() does not provide error = %v, zoneID %v", err, tt.fields.ZoneID)
				}
				if !strings.HasPrefix(err.Error(), tt.fields.ExpectedErrorMsg) {
					t.Errorf("GetJWKs() does not provide expected error message = %v", err.Error())
				}
			} else if jwks == nil {
				t.Errorf("GetJWKs() returns nil = %v, zoneID %v", err, tt.fields.ZoneID)
			}
		})
	}
}

func NewRouter() (r *mux.Router) {
	r = mux.NewRouter()
	r.HandleFunc("/oauth2/certs", ReturnJWKS).Methods("GET").Headers("x-zone_uuid", "zone-id")
	r.HandleFunc("/oauth2/certs", ReturnInvalidZone).Methods("GET").Headers("x-zone_uuid", "unknown-zone-id")
	r.HandleFunc("/oauth2/certs", ReturnInvalidZone).Methods("GET").Headers("x-zone_uuid", "deleted-zone-id")
	r.HandleFunc("/oauth2/certs", ReturnInvalidJWKS).Methods("GET").Headers("x-zone_uuid", "provide-invalidJWKS")
	return r
}

func ReturnJWKS(writer http.ResponseWriter, request *http.Request) {
	_, _ = writer.Write([]byte(jwksJSONString))
}

func ReturnInvalidJWKS(writer http.ResponseWriter, request *http.Request) {
	_, _ = writer.Write([]byte("\"kid\":\"default-kid-ias\""))
}

func ReturnInvalidZone(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(400)
}
