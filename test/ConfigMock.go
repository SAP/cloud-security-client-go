package test

type MockConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
}

func (c MockConfig) GetClientID() string {
	return c.ClientID
}

func (c MockConfig) GetClientSecret() string {
	return c.ClientSecret
}

func (c MockConfig) GetBaseURL() string {
	return c.BaseURL
}
