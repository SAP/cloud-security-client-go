<h1>Client library under development. Not yet ready for productive use<h1>

# Go Cloud Security Integration

## Core
Parsing claims of the JWT and validation the token signature, audience, issuer, … 

## Token Client
Any interaction with the Authorization Server e.g. fetching token keys or token exchange flows

## Env
Parsing of environment provided by the Authorization Server e.g. xsuaa


# Usage

The client library works as a middleware and has to be instantiated with `NewAuthMiddelware`. The Middleware exposes a `Handler` which implements the standard `http/Handler` interface. Thus it can be used easily e.g. in an `gorilla/mux` router or a plain `http/Server` implementation.

Upon successful validation of the OIDC Token the token is available in the context of the current request. The property can be specified with the `UserContext` option and has to be cased to `(*core.OIDCClaims)` for the property accessors to be available.  
 
### Sample Code

```go
r := mux.NewRouter()

authMiddleware := core.NewAuthMiddleware(core.Options{
    UserContext:  "user",
    OAuthConfig:  env.GetIASConfig(),
    ErrorHandler: nil,
})
r.Use(authMiddleware.Handler)

r.HandleFunc("/helloWorld", helloWorld).Methods("GET")

address := ":8080"
log.Println("Starting server on address", address)
err := http.ListenAndServe(address, handlers.LoggingHandler(os.Stdout, r))
if err != nil {
    panic(err)
}
```
