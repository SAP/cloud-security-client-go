package env

import (
	"errors"
	"github.com/cloudfoundry-community/go-cfenv"
	"log"
)

type IASConfig struct {
	clientID     string
	clientSecret string
	baseURL      string
}

func GetIASConfig() *IASConfig {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			log.Fatal("Could not read cf env")
		}
		ias, e := appEnv.Services.WithName("iasb")
		if e != nil {
			log.Fatal("No ias instance bound to the application")
		} else {
			config = IASConfig{}
			e := config.parseEnv(ias.Credentials)
			if e != nil {
				log.Fatal("error during parsing of ias environment: ", e)
			}
		}
		// do stuff
	case KUBERNETES:
		log.Fatal("kubernetes env detected but not yet supported")
		// do stuff
	}
	return &config
}

func (c IASConfig) GetClientID() string {
	return c.clientID
}

func (c IASConfig) GetClientSecret() string {
	return c.clientSecret
}

func (c IASConfig) GetBaseURL() string {
	return c.baseURL
}

func (c *IASConfig) parseEnv(credentials map[string]interface{}) error {
	if clientID, ok := credentials["clientid"]; !ok {
		return errors.New("unable to find property clientid in environment")
	} else {
		c.clientID = clientID.(string)
	}
	if clientSecret, ok := credentials["clientsecret"]; !ok {
		return errors.New("unable to find property clientsecret in environment")
	} else {
		c.clientSecret = clientSecret.(string)
	}
	if baseURL, ok := credentials["url"]; !ok {
		return errors.New("unable to find property url in environment")
	} else {
		c.baseURL = baseURL.(string)
	}
	return nil
}
