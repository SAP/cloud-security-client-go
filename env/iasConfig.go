// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
)

const iasServiceName = "identity"
const iasSecretKeyDefault = "credentials"
const vcapServicesEnvKey = "VCAP_SERVICES"
const iasConfigPathKey = "IAS_CONFIG_PATH"
const iasConfigPathDefault = "/etc/secrets/sapbtp/identity"

// VCAPServices is the Cloud Foundry environment variable that stores information about services bound to the application
type VCAPServices struct {
	Identity []struct {
		Credentials DefaultIdentity `json:"credentials"`
	} `json:"identity"`
}

// Identity interface has to be implemented to instantiate NewMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type Identity interface {
	GetClientID() string                // Returns the client id of the oAuth client.
	GetClientSecret() string            // Returns the client secret. Optional
	GetURL() string                     // Returns the url to the DefaultIdentity tenant. E.g. https://abcdefgh.accounts.ondemand.com
	GetDomains() []string               // Returns the domains of the DefaultIdentity service. E.g. ["accounts.ondemand.com"]
	GetAppTID() string                  // Returns the app tid uuid and replaces zone uuid in future Optional
	GetProofTokenURL() string           // Returns the proof token url. Optional
	GetCertificate() string             // Returns the client certificate. Optional
	GetKey() string                     // Returns the client certificate key. Optional
	GetCertificateExpiresAt() string    // Returns the client certificate expiration time. Optional
	IsCertificateBased() bool           // Returns true, in case GetCertificate() and GetKey returns non-empty values
	GetAuthorizationInstanceID() string // Returns the AMS instance id if authorization is enabled
	GetAuthorizationBundleURL() string  // Returns the AMS Bundle URL if authorization is enabled
}

// DefaultIdentity represents the parsed credentials from the ias binding
type DefaultIdentity struct {
	ClientID                string   `json:"clientid"`
	ClientSecret            string   `json:"clientsecret"`
	Domains                 []string `json:"domains"`
	URL                     string   `json:"url"`
	AppTID                  string   `json:"app_tid"`
	ProofTokenURL           string   `json:"prooftoken_url"`
	OsbURL                  string   `json:"osb_url"`
	Certificate             string   `json:"certificate"`
	Key                     string   `json:"key"`
	CertificateExpiresAt    string   `json:"certificate_expires_at"`
	AuthorizationInstanceID string   `json:"authorization_instance_id"`
	AuthorizationBundleURL  string   `json:"authorization_bundle_url"`
}

// ParseIdentityConfig parses the IAS config from the applications environment
func ParseIdentityConfig() (Identity, error) {
	switch getPlatform() { //nolint:exhaustive // Unknown case is handled by default
	case cloudFoundry:
		var vcapServices VCAPServices
		vcapServicesString := os.Getenv(vcapServicesEnvKey)
		err := json.Unmarshal([]byte(vcapServicesString), &vcapServices)
		if err != nil {
			return nil, fmt.Errorf("cannot parse vcap services: %w", err)
		}
		if len(vcapServices.Identity) == 0 {
			return nil, fmt.Errorf("no '%s' service instance bound to the application", iasServiceName)
		}
		if len(vcapServices.Identity) > 1 {
			return nil, fmt.Errorf("more than one '%s' service instance bound to the application. This is currently not supported", iasServiceName)
		}
		return &vcapServices.Identity[0].Credentials, nil
	case kubernetes:
		var secretPath = os.Getenv(iasConfigPathKey)
		if secretPath == "" {
			secretPath = iasConfigPathDefault
		}
		identities, err := readServiceBindings(secretPath)
		if err != nil || len(identities) == 0 {
			return nil, fmt.Errorf("cannot find '%s' service binding from secret path '%s'", iasServiceName, secretPath)
		} else if len(identities) > 1 {
			return nil, fmt.Errorf("found more than one '%s' service instance from secret path '%s'. This is currently not supported", iasServiceName, secretPath)
		}
		return &identities[0], nil
	default:
		return nil, fmt.Errorf("unable to parse '%s' service config: unknown environment detected", iasServiceName)
	}
}

func readServiceBindings(secretPath string) ([]DefaultIdentity, error) {
	instancesBound, err := os.ReadDir(secretPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read service directory '%s' for identity service: %w", secretPath, err)
	}
	identities := []DefaultIdentity{}
	for _, instanceBound := range instancesBound {
		if !instanceBound.IsDir() {
			continue
		}
		serviceInstancePath := path.Join(secretPath, instanceBound.Name())
		instanceSecretFiles, err := os.ReadDir(serviceInstancePath)
		if err != nil {
			return nil, fmt.Errorf("cannot read service instance directory '%s' for '%s' service instance '%s': %w", serviceInstancePath, iasServiceName, instanceBound.Name(), err)
		}

		identity, err := readCredentialsFile(serviceInstancePath, instanceSecretFiles)
		if identity == nil || err != nil {
			identity, err = readSecretFiles(serviceInstancePath, instanceSecretFiles)
			if err != nil {
				return nil, err
			}
		}
		identities = append(identities, *identity)
	}
	return identities, nil
}

func readCredentialsFile(serviceInstancePath string, instanceSecretFiles []os.DirEntry) (*DefaultIdentity, error) {
	result := DefaultIdentity{}
	for _, instanceSecretFile := range instanceSecretFiles {
		if instanceSecretFile.IsDir() || instanceSecretFile.Name() != iasSecretKeyDefault {
			continue
		}
		serviceInstanceCredentialsPath := path.Join(serviceInstancePath, instanceSecretFile.Name())

		credentials, err := os.ReadFile(serviceInstanceCredentialsPath) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("cannot read content from '%s': %w", serviceInstanceCredentialsPath, err)
		}
		err = json.Unmarshal(credentials, &result)
		if err != nil {
			return nil, fmt.Errorf("cannot unmarshal json content from '%s': %w", serviceInstanceCredentialsPath, err)
		}
		return &result, nil
	}
	return nil, nil
}

func readSecretFiles(serviceInstancePath string, instanceSecretFiles []os.DirEntry) (*DefaultIdentity, error) {
	var result DefaultIdentity
	resType := reflect.TypeOf(result)
	for _, resField := range reflect.VisibleFields(resType) {
		tag := resField.Tag.Get("json")
		if tag == "" {
			continue
		}
		for _, instanceSecretFile := range instanceSecretFiles {
			if instanceSecretFile.Name() == tag {
				content, err := os.ReadFile(path.Join(serviceInstancePath, instanceSecretFile.Name())) //nolint:gosec
				if err != nil {
					return nil, fmt.Errorf("cannot read content from '%s': %w", instanceSecretFile.Name(), err)
				}
				if resField.Type.Kind() != reflect.String {
					err := json.Unmarshal(content, reflect.ValueOf(&result).Elem().FieldByName(resField.Name).Addr().Interface())
					if err != nil {
						return nil, fmt.Errorf("cannot unmarshal json content from '%s': %w", instanceSecretFile.Name(), err)
					}
				} else {
					if !reflect.ValueOf(&result).Elem().FieldByName(resField.Name).CanSet() {
						continue
					}
					reflect.ValueOf(&result).Elem().FieldByName(resField.Name).SetString(string(content))
				}
			}
		}
	}
	return &result, nil
}

// GetClientID implements the env.Identity interface.
func (c DefaultIdentity) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the env.Identity interface.
func (c DefaultIdentity) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the env.Identity interface.
func (c DefaultIdentity) GetURL() string {
	return c.URL
}

// GetDomains implements the env.Identity interface.
func (c DefaultIdentity) GetDomains() []string {
	return c.Domains
}

// GetAppTID implements the env.Identity interface and replaces GetZoneUUID in future
func (c DefaultIdentity) GetAppTID() string {
	return c.AppTID
}

// GetProofTokenURL implements the env.Identity interface.
func (c DefaultIdentity) GetProofTokenURL() string {
	return c.ProofTokenURL
}

// GetOsbURL implements the env.Identity interface.
func (c DefaultIdentity) GetOsbURL() string {
	return c.OsbURL
}

// GetCertificate implements the env.Identity interface.
func (c DefaultIdentity) GetCertificate() string {
	return c.Certificate
}

// IsCertificateBased implements the env.Identity interface.
func (c DefaultIdentity) IsCertificateBased() bool {
	return c.Certificate != "" && c.Key != ""
}

// GetKey implements the env.Identity interface.
func (c DefaultIdentity) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the env.Identity interface.
func (c DefaultIdentity) GetCertificateExpiresAt() string {
	return c.CertificateExpiresAt
}

// GetAuthorizationInstanceID implements the env.Identity interface.
func (c DefaultIdentity) GetAuthorizationInstanceID() string {
	return c.AuthorizationInstanceID
}

// GetAuthorizationBundleURL implements the env.Identity interface.
func (c DefaultIdentity) GetAuthorizationBundleURL() string {
	return c.AuthorizationBundleURL
}
