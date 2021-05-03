// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
)

const iasServiceName = "identity"
const vcapServicesEnvKey = "VCAP_SERVICES"

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
	Domain               string    `json:"domain"`
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
			return nil, fmt.Errorf("no '" + iasServiceName + "' service instance bound to the application")
		}
		if len(vcapServices.Identity) > 1 {
			return nil, fmt.Errorf("more than one '" + iasServiceName + "' service instance bound to the application. This is currently not supported")
		}
		return &vcapServices.Identity[0].Credentials, nil
	case kubernetes:
		return nil, fmt.Errorf("unable to parse ias config: kubernetes env detected but not yet supported")
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
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

// GetDomain implements the auth.OAuthConfig interface.
func (c Identity) GetDomain() string {
	return c.Domain
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
