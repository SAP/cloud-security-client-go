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

var testConfig *IASConfig = &IASConfig{
	ClientID:     "cef76757-de57-480f-be92-1d8c1c7abf16",
	ClientSecret: "the_CLIENT.secret:3[/abc",
	Domain:       "accounts400.ondemand.com",
	URL:          "https://mytenant.accounts400.ondemand.com",
}

func TestGetIASConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    *IASConfig
		wantErr bool
	}{
		{
			name:    "all present",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "multiple bindings",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
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

func TestGetIASConfigInUserProvidedService(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		arg     string
		want    *IASConfig
		wantErr bool
	}{
		{
			name:    "one ups, correct name",
			env:     "{\"user-provided\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"identity\",\"label\":\"user-provided\",\"name\":\"identity\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]}]}",
			arg:     "identity",
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "multiple ups, one with correct name",
			env:     "{\"user-provided\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"another-ups\",\"label\":\"user-provided\",\"name\":\"another-ups\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"identity\",\"label\":\"user-provided\",\"name\":\"identity\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]}]}",
			arg:     "identity",
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "multiple ups with same name",
			env:     "{\"user-provided\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"identity\",\"label\":\"user-provided\",\"name\":\"identity\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"identity\",\"label\":\"user-provided\",\"name\":\"identity\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]}]}",
			arg:     "identity",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "multiple ups, none with correct name",
			env:     "{\"user-provided\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"another-ups\",\"label\":\"user-provided\",\"name\":\"another-ups\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"yet-another-ups\",\"label\":\"user-provided\",\"name\":\"yet-another-ups\",\"syslog_drain_url\":\"\",\"tags\":[],\"volume_mounts\":[]}]}",
			arg:     "identity",
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
			got, err := GetIASConfigInUserProvidedService(tt.arg)
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
		return fmt.Errorf("error preparing test: could not set env VCAP_SERVICES: %v", err)
	}
	err = os.Setenv("VCAP_APPLICATION", "{}")
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env VCAP_APPLICATION: %v", err)
	}
	return nil
}

func clearTestEnv() error {
	err := os.Unsetenv("VCAP_SERVICES")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_SERVICES: %v", err)
	}
	err = os.Unsetenv("VCAP_APPLICATION")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_APPLICATION/VCAP_SERVICES: %v", err)
	}
	return nil
}
