# Go Cloud Security Integration

[![PkgGoDev](https://pkg.go.dev/badge/github.com/sap/cloud-security-client-go/auth)](https://pkg.go.dev/github.com/sap/cloud-security-client-go/auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/SAP/cloud-security-client-go)](https://goreportcard.com/report/github.com/SAP/cloud-security-client-go)
[![REUSE status](https://api.reuse.software/badge/github.com/SAP/cloud-security-client-go)](https://api.reuse.software/info/github.com/SAP/cloud-security-client-go)
[![Fosstars security rating](https://raw.githubusercontent.com/SAP/cloud-security-client-go/fosstars-report/fosstars_badge.svg)](https://github.com/SAP/cloud-security-client-go/blob/fosstars-report/fosstars_report.md)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/SAP/cloud-security-client-go.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/SAP/cloud-security-client-go/alerts/)

## Description
Client Library in GoLang for application developers requiring authentication with the SAP Identity Authentication Service (IAS). The library provides means for validating the Open ID Connect Token (OIDC) and accessing authentication information like user uuid, user attributes and audiences from the token.

## Supported Environments
- Cloud Foundry
- Kubernetes/Kyma as of 0.11 version

## Requirements
In order to make use of this client library your application should be integrated with the [SAP Identity Authentication Service (IAS)](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/LATEST/en-US/d17a116432d24470930ebea41977a888.html).

## Download and Installation
This project is a library for applications or services and does not run standalone.
When integrating, the most important package is `auth`. It contains means for parsing claims of the JWT and validation 
the token signature, audience, issuer and more.

The client library works as a middleware and has to be instantiated with `NewMiddelware`. For authentication there are options: 
 - Ready-to-use **Middleware Handler**: The `AuthenticationHandler` which implements the standard `http/Handler` interface. Thus, it can be used easily e.g. in an `gorilla/mux` router or a plain `http/Server` implementation. The claims can be retrieved with `auth.GetClaims(req)` in the HTTP handler.
 - **Authenticate func**: More flexible, can be wrapped with an own middleware func to propagate the users claims. 

### Service configuration in Kubernetes environment
To access service instance configurations from the application, Kubernetes secrets need to be provided as files in a volume mounted on application's container. Library will look up the configuration files on the `mountPath:"/etc/secrets/sapbtp/identity/<YOUR IAS INSTANCE NAME>"`.


### Sample Code

```go
r := mux.NewRouter()

config, err := env.GetIASConfig()
if err != nil {
    panic(err)
}
authMiddleware := auth.NewMiddleware(config, auth.Options{})
r.Use(authMiddleware.AuthenticationHandler)

r.HandleFunc("/helloWorld", helloWorld).Methods("GET")

address := ":8080"
log.Println("Starting server on address", address)
err = http.ListenAndServe(address, handlers.LoggingHandler(os.Stdout, r))
if err != nil {
    panic(err)
}   
```
Full example: [samples/middleware.go](samples/middleware.go)

### Proof of Possession
Additionally, you may want to make sure, whether you have been called by a trust-worthy consumer. Trust between applications/services is established with certificates in principle. So, in case of mTls based communication, you can check, whether the token was issued for the consumer. This can be done by
 performing the JWT Certificate Thumbprint X5t confirmation method's validation. See specification [RFC 8705](https://tools.ietf.org/html/rfc8705#section-3.1). It can be done in the following manner:
 
```go
func myEndpoint(w http.ResponseWriter, r *http.Request) {
    err := auth.ValidateX5tThumbprint(auth.ClientCertificateFromCtx(r), auth.TokenFromCtx(r))
    if err != nil {
        panic(err)
    }
    ...
}
```

### Testing
The client library offers an OIDC Mock Server with means to create arbitrary tokens for testing purposes. Examples for the usage of the Mock Server in combination with the OIDC Token Builder can be found in [auth/middleware_test.go](auth/middleware_test.go) 

## Current limitations
Not Known.

## How to obtain support
In case of questions or bug or reports please open a GitHub Issue in this repository.

## Contribution
Contributions are welcome! Please open a pull request and we will provide feedback as soon as possible.

Note that this project makes use of golangci-lint.  
To make use of our Makefile, please make sure you have installed [golangci-lint](https://golangci-lint.run/usage/install/#local-installation) on your local machine.

All prerequisites for a pull request can then be checked with `make pull-request`. 

More information can be found in [CONTRIBUTING.md](./CONTRIBUTING.md)

## Licensing
Please see our [LICENSE](./LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available via the [REUSE tool](https://api.reuse.software/info/github.com/SAP/cloud-security-client-go).
