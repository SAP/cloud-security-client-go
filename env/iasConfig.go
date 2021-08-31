// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
)

const iasServiceName = "identity"
const vcapServicesEnvKey = "VCAP_SERVICES"
const iasConfigPathKey = "IAS_CONFIG_PATH"
const iasConfigPathDefault = "/etc/secrets/sapcp/ias"

// VCAPServices is the Cloud Foundry environment variable that stores information about services bound to the application
type VCAPServices struct {
	Identity []struct {
		Credentials Identity `json:"credentials"`
	} `json:"identity"`
}

// Identity represents the parsed credentials from the ias binding
type Identity struct {
	ClientID             string    `json:"clientid"`
	ClientSecret         string    `json:"clientsecret"`
	Domains              []string  `json:"domains"`
	URL                  string    `json:"url"`
	ZoneUUID             uuid.UUID `json:"zone_uuid"`
	ProofTokenURL        string    `json:"prooftoken_url"`
	OsbURL               string    `json:"osb_url"`
	Certificate          string    `json:"certificate"`
	Key                  string    `json:"key"`
	CertificateExpiresAt string    `json:"certificate_expires_at"`
}

// GetIASConfig parses the IAS config from the applications environment
func GetIASConfig() (*Identity, error) {
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
			return nil, fmt.Errorf("cannot find service binding on secret path '%s'", secretPath)
		} else if len(identities) > 1 {
			return nil, fmt.Errorf("found more than one service instance on secret path '%s'. This is currently not supported", secretPath)
		}
		return &identities[0], nil
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
}

func readServiceBindings(secretPath string) ([]Identity, error) {
	bindingFiles, err := ioutil.ReadDir(secretPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read service directory '%s' for ias service: %w", secretPath, err)
	}
	identities := []Identity{}
	for _, instancesBoundDir := range bindingFiles {
		if !instancesBoundDir.IsDir() {
			continue
		}
		serviceInstancePath := path.Join(secretPath, instancesBoundDir.Name())
		instancePropertyFiles, err := ioutil.ReadDir(serviceInstancePath)
		if err != nil {
			return nil, fmt.Errorf("cannot read service instance directory '%s' for ias service instance '%s': %w", serviceInstancePath, instancesBoundDir.Name(), err)
		}
		instancePropertiesJSON, err := readPropertyFilesToJSON(serviceInstancePath, instancePropertyFiles)
		if err != nil {
			return nil, err
		}
		identity := Identity{}
		if err := json.Unmarshal(instancePropertiesJSON, &identity); err != nil {
			return nil, fmt.Errorf("cannot unmarshal json content: %w", err)
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func readPropertyFilesToJSON(serviceInstancePath string, instancePropertyFiles []fs.FileInfo) ([]byte, error) {
	instancePropertiesMap := make(map[string]interface{})
	for _, instancePropertyFile := range instancePropertyFiles {
		if instancePropertyFile.IsDir() {
			continue
		}
		serviceInstancePropertyPath := path.Join(serviceInstancePath, instancePropertyFile.Name())
		var property []byte
		property, err := ioutil.ReadFile(serviceInstancePropertyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read property file '%s' from '%s': %w", instancePropertyFile.Name(), serviceInstancePropertyPath, err)
		}
		if instancePropertyFile.Name() == "domains" {
			var domains []string
			if err := json.Unmarshal(property, &domains); err != nil {
				return nil, fmt.Errorf("cannot unmarshal content of property file '%s' from '%s': %w", instancePropertyFile.Name(), serviceInstancePropertyPath, err)
			}
			instancePropertiesMap[instancePropertyFile.Name()] = domains
		} else {
			instancePropertiesMap[instancePropertyFile.Name()] = string(property)
		}
	}
	instancePropertiesJSON, err := json.Marshal(instancePropertiesMap)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal map into json: %w", err)
	}
	return instancePropertiesJSON, nil
}

// GetClientID implements the auth.OAuthConfig interface.
func (c Identity) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the auth.OAuthConfig interface.
func (c Identity) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the auth.OAuthConfig interface.
func (c Identity) GetURL() string {
	return c.URL
}

// GetDomains implements the auth.OAuthConfig interface.
func (c Identity) GetDomains() []string {
	return c.Domains
}

// GetZoneUUID implements the auth.OAuthConfig interface.
func (c Identity) GetZoneUUID() uuid.UUID {
	return c.ZoneUUID
}

// GetProofTokenURL implements the auth.OAuthConfig interface.
func (c Identity) GetProofTokenURL() string {
	return c.ProofTokenURL
}

// GetOsbURL implements the auth.OAuthConfig interface.
func (c Identity) GetOsbURL() string {
	return c.OsbURL
}

// GetCertificate implements the auth.OAuthConfig interface.
func (c Identity) GetCertificate() string {
	return c.Certificate
}

// GetKey implements the auth.OAuthConfig interface.
func (c Identity) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the auth.OAuthConfig interface.
func (c Identity) GetCertificateExpiresAt() string {
	return c.CertificateExpiresAt
}
