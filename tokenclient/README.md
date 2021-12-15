# Go Token Client
This ``tokenclient`` module provides slim client to call ``/oauth2/token`` identity service endpoints as specified [here](https://docs.cloudfoundry.org/api/uaa/version/74.1.0/index.html#token). Furthermore, it introduces a new API to support the following token flow:

* **Client Credentials Flow**.  
The Client Credentials ([RFC 6749, section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)) is used by clients to obtain an access token outside of the context of a user. It is used for non interactive applications (a CLI, a batch job, or for service-2-service communication) where the token is issued to the client application itself, instead of an end user for accessing resources without principal propagation. 

## Initialization
Instantiate TokenFlows which makes by default use of a simple `http.Client`, which should NOT be used in production.

```go
config, err := env.ParseIdentityConfig()
if err != nil {
    panic(err)
}

tokenFlows, err := tokenclient.NewTokenFlows(config, tokenclient.Options{HTTPClient: <your http.Client>})
if err != nil {
    panic(err)
}
```

## Get TokenFlows from middleware
In case you leverage `auth.NewMiddleware`, you can also get an initialized TokenFlows from there:

```go
tokenFlows, err := authMiddleware.GetTokenFlows()
if err != nil {
    panic(err)
}
```

## Usage
The TokenFlows allows applications to easily create and execute each flow.

### Client Credentials Token Flow
Obtain a client credentials token:

````go
params := map[string]string{
	"resource": "urn:sap:identity:consumer:clientid:<<consumer identifier>>",
}
customerTenantUrl := oidcToken.Issuer()
encodedToken, err := tokenFlows.ClientCredentials(context.TODO(), customerTenantUrl, tokenclient.RequestOptions{Params: params})
if err != nil {
    log.Fatal(err)
}

// optionally you can parse the token to access its claims
token, e := auth.NewToken(encodedToken)
if e != nil {
    log.Fatal(err)
}
````
In the above sample the ``resource`` parameter specifies the consumer's client id the token is targeted at.

## Outlook: Cache

The `TokenFlows` will cache tokens internally.

