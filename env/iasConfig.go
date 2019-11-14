package env

import (
	"github.com/cloudfoundry-community/go-cfenv"
	"log"
)

type IASConfig struct {
	clientID     string // pointer because it can be nil in contrast to string (needed when property is not set in json)
	clientSecret string
	sbUrl        string
}

func getIASConfig() *IASConfig {
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
			config.parse(ias.Credentials)
		}
		// do stuff
	case KUBERNETES:
		// do stuff
	}
	return &config
}

func (iasConfig IASConfig) GetClientID() string {
	return iasConfig.clientID
}

func (iasConfig IASConfig) GetClientSecret() string {
	return iasConfig.clientSecret
}

func (iasConfig IASConfig) GetSbURL() string {
	return iasConfig.sbUrl
}

func (config *IASConfig) parse(credentials map[string]interface{}) {
	(*config).clientID = credentials["username"].(string)
	(*config).clientSecret = credentials["password"].(string)
}
