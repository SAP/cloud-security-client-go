package env

type XsuaaConfig struct {
	clientID       string
	clientSecret   string
	subDomain      string
	identityZoneID string
	xsappName      string
	sbURL          string
	apiURL         string
	uaaDomain      string
}

func (xsuaaConfig XsuaaConfig) getClientID() string {
	return xsuaaConfig.clientID
}

func (xsuaaConfig XsuaaConfig) getClientSecret() string {
	return xsuaaConfig.clientSecret
}

func (xsuaaConfig XsuaaConfig) getSubDomain() string {
	return xsuaaConfig.subDomain
}

func (xsuaaConfig XsuaaConfig) getIdentityZoneID() string {
	return xsuaaConfig.identityZoneID
}

func (xsuaaConfig XsuaaConfig) getXsAppName() string {
	return xsuaaConfig.xsappName
}

func (xsuaaConfig XsuaaConfig) getSbURL() string {
	return xsuaaConfig.sbURL
}

func (xsuaaConfig XsuaaConfig) getApiURL() string {
	return xsuaaConfig.apiURL
}

func (xsuaaConfig XsuaaConfig) getUaaDomain() string {
	return xsuaaConfig.uaaDomain
}

func (xsuaaConfig XsuaaConfig) Parse(credentials map[string]interface{}) {
	xsuaaConfig.clientID = credentials["clientid"].(string)
	xsuaaConfig.clientSecret = credentials["clientsecret"].(string)
	xsuaaConfig.subDomain = credentials["identityzone"].(string)
	xsuaaConfig.identityZoneID = credentials["identityzoneid"].(string)
	xsuaaConfig.xsappName = credentials["xsappname"].(string)
	xsuaaConfig.sbURL = credentials["sburl"].(string)
	xsuaaConfig.apiURL = credentials["apiurl"].(string)
	xsuaaConfig.uaaDomain = credentials["uaadomain"].(string)
}
