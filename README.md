# Go Cloud Security Integration

[![PkgGoDev](https://pkg.go.dev/badge/github.com/sap/cloud-security-client-go/auth)](https://pkg.go.dev/github.com/sap/cloud-security-client-go/auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/SAP/cloud-security-client-go)](https://goreportcard.com/report/github.com/SAP/cloud-security-client-go)
[![REUSE status](https://api.reuse.software/badge/git.fsfe.org/reuse/api)](https://api.reuse.software/info/git.fsfe.org/reuse/api)

Client Library in GoLang for application developers requiring authentication with the Identity Authentication Service (IAS). The library provides means for validating the Open ID Connect Token (OIDC) and accessing authentication information like user uuid, user attributes and audiences from the token.

## Auth
Parsing claims of the JWT and validation the token signature, audience, issuer, … 

## OIDC Client
Any interaction with the Authorization Server e.g. OIDC discovery and fetching token keys

## Env
Parsing of environment provided by the Authorization Server e.g. IAS broker


# Usage

The client library works as a middleware and has to be instantiated with `NewAuthMiddelware`. For authentication there are options: 
 - Ready-to-use **Middleware Handler**: The `Handler` which implements the standard `http/Handler` interface. Thus, it can be used easily e.g. in an `gorilla/mux` router or a plain `http/Server` implementation. The property name can be specified with the `UserContext` option and has to be type asserted to `(*core.OIDCClaims)` for the property accessors to be available.
 - **Authenticate func**: More flexible, can be wrapped with an own middleware func to propagate the users claims. 

 
### Sample Code

```go
r := mux.NewRouter()

config, err := env.GetIASConfig()
if err != nil {
    panic(err)
}
authMiddleware := auth.NewAuthMiddleware(config, auth.Options{
    UserContext:  "user"
})
r.Use(authMiddleware.Handler)

r.HandleFunc("/helloWorld", helloWorld).Methods("GET")

address := ":8080"
log.Println("Starting server on address", address)
err = http.ListenAndServe(address, handlers.LoggingHandler(os.Stdout, r))
if err != nil {
    panic(err)
}   
```
Full example: [samples/middleware.go](samples/middleware.go)

### Testing
The client library offers an OIDC Mock Server with means to create arbitrary tokens for testing purposes. Examples for the usage of the Mock Server in combination with the OIDC Token Builder can be found in [auth/middleware_test.go](auth/middleware_test.go) 

### Current limitations
The client library does not yet provide support for IAS custom domains. This limitation will be overcome within the next few weeks, once there is full support for that from IAS and IAS-Broker side.

test
