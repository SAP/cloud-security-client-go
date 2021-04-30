// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"testing"
)

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
