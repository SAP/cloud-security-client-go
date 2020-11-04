# Go Cloud Security Integration

Client Library in GoLang for application developers requiring authentication with the Identity Authentication Service (IAS). The library provides means for validating the Open ID Connect Token (OIDC) and accessing authentication information like user uuid, user attributes and audiences from the token.

## Auth
Parsing claims of the JWT and validation the token signature, audience, issuer, … 

## OIDC Client
Any interaction with the Authorization Server e.g. OIDC discovery and fetching token keys

## Env
Parsing of environment provided by the Authorization Server e.g. IAS broker


# Usage

The client library works as a middleware and has to be instantiated with `NewAuthMiddelware`. The Middleware exposes a `Handler` which implements the standard `http/Handler` interface. Thus it can be used easily e.g. in an `gorilla/mux` router or a plain `http/Server` implementation.

Upon successful validation of the OIDC Token the token is available in the context of the current request. The property name can be specified with the `UserContext` option and has to be casted to `(*core.OIDCClaims)` for the property accessors to be available.  
 
### Sample Code

```go
r := mux.NewRouter()

config, err := env.GetIASConfig()
if err != nil {
    panic(err)
}
authMiddleware := auth.NewAuthMiddleware(config, auth.Options{
    UserContext:  "user",
    ErrorHandler: nil,
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

### Current limitations
The client library does not yet provide support for multi tenant applications, where the SaaS tenants use different IAS tenants than the provider tenant. 
This limitation will be overcome within the next few weeks, once there is full support for that from IAS and IAS-Broker side.