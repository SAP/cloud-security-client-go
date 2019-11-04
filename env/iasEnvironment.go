package env

type IASConfig struct {
	clientID     string
	clientSecret string
	sbUrl        string
}

var defaultIASConfig IASConfig

func (iasConfig IASConfig) getClientID() string {
	return iasConfig.clientID
}

func (iasConfig IASConfig) getClientSecret() string {
	return iasConfig.clientSecret
}

func (iasConfig IASConfig) getSbURL() string {
	return iasConfig.sbUrl
}
