// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"errors"
	"fmt"
	"github.com/cloudfoundry-community/go-cfenv"
	"strings"
)

const iasServiceName = "identity"

type IASConfig struct {
	ClientID     string
	ClientSecret string
	Domain       string
	URL          string
}

func GetIASConfig() (*IASConfig, error) {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			return nil, fmt.Errorf("could not read cf env")
		}
		ias, e := appEnv.Services.WithLabel(iasServiceName)
		if e != nil {
			return nil, fmt.Errorf("no '" + iasServiceName + "' service instance bound to the application")
		} else if len(ias) > 1 {
			return nil, fmt.Errorf("more than one '" + iasServiceName + "' service instance bound to the application")
		} else {
			config = IASConfig{}
			e := config.parseEnv(ias[0].Credentials)
			if e != nil {
				return nil, fmt.Errorf("error during parsing of "+iasServiceName+" environment: %v", e)
			}
		}
	case KUBERNETES:
		return nil, fmt.Errorf("unable to parse ias config: kubernetes env detected but not yet supported")
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
	return &config, nil
}

func GetIASConfigInUserProvidedService(serviceInstanceName string) (*IASConfig, error) {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			return nil, fmt.Errorf("could not read cf env")
		}
		userProvided, e := appEnv.Services.WithLabel("user-provided")
		if e != nil {
			return nil, fmt.Errorf("no " + iasServiceName + " instance bound to the application")
		}

		var instance cfenv.Service
		var found bool
		for _, service := range userProvided {
			if strings.EqualFold(serviceInstanceName, service.Name) {
				if !found {
					found = true
					instance = service
				} else {
					return nil, fmt.Errorf("more than one user-provided service with name '" + serviceInstanceName + "' bound to the application")
				}
			}
		}

		e = config.parseEnv(instance.Credentials)
		if e != nil {
			return nil, fmt.Errorf("error during parsing of "+serviceInstanceName+" in user-provided environment: ", e)
		}
	case KUBERNETES:
		return nil, fmt.Errorf("unable to parse ias config: kubernetes env detected but not yet supported")
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
	return &config, nil
}

func (c IASConfig) GetClientID() string {
	return c.ClientID
}

func (c IASConfig) GetClientSecret() string {
	return c.ClientSecret
}

func (c IASConfig) GetURL() string {
	return c.URL
}

func (c IASConfig) GetDomain() string {
	return c.Domain
}

func (c *IASConfig) parseEnv(credentials map[string]interface{}) error {
	if clientID, ok := credentials["clientid"]; !ok {
		return errors.New("unable to find property clientid in environment")
	} else {
		c.ClientID = clientID.(string)
	}
	if clientSecret, ok := credentials["clientsecret"]; !ok {
		return errors.New("unable to find property clientsecret in environment")
	} else {
		c.ClientSecret = clientSecret.(string)
	}
	if baseURL, ok := credentials["url"]; !ok {
		return errors.New("unable to find property url in environment")
	} else {
		c.URL = baseURL.(string)
	}
	if domain, ok := credentials["domain"]; !ok {
		return errors.New("unable to find property domain in environment")
	} else {
		c.Domain = domain.(string)
	}
	return nil
}
