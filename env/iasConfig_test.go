// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"fmt"
	"os"
	"reflect"
	"testing"
)

var testConfig *Identity = &Identity{
	ClientID:     "cef76757-de57-480f-be92-1d8c1c7abf16",
	ClientSecret: "the_CLIENT.secret:3[/abc",
	Domains:      []string{"accounts400.ondemand.com", "my.arbitrary.domain"},
	URL:          "https://mytenant.accounts400.ondemand.com",
}

func TestGetIASConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    *Identity
		wantErr bool
	}{
		{
			name:    "all present",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domains\":[\"accounts400.ondemand.com\",\"my.arbitrary.domain\"],\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "multiple bindings",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domains\":[\"accounts400.ondemand.com\",\"my.arbitrary.domain\"],\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setTestEnv(tt.env)
			if err != nil {
				t.Error(err)
			}
			got, err := GetIASConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIASConfigInUserProvidedService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIASConfigInUserProvidedService() got = %v, want %v", got, tt.want)
			}
			err = clearTestEnv()
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func setTestEnv(vcapServices string) error {
	err := os.Setenv("VCAP_SERVICES", vcapServices)
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env VCAP_SERVICES: %w", err)
	}
	err = os.Setenv("VCAP_APPLICATION", "{}")
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env VCAP_APPLICATION: %w", err)
	}
	return nil
}

func clearTestEnv() error {
	err := os.Unsetenv("VCAP_SERVICES")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_SERVICES: %w", err)
	}
	err = os.Unsetenv("VCAP_APPLICATION")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_APPLICATION/VCAP_SERVICES: %w", err)
	}
	return nil
}
