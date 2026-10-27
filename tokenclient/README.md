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
`ClientCredentials` keeps its existing signature and uses `/oauth2/token` by default, without an OIDC discovery request. `RequestOptions.Params` and `RequestOptions.TokenEndpoint` remain available.

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

To use a different endpoint on the same tenant, supply an absolute path:

```go
encodedToken, err := tokenFlows.ClientCredentials(ctx, customerTenantUrl, tokenclient.RequestOptions{
    Params:        params,
    TokenEndpoint: "/oauth/token",
})
```

The path must start with a single `/` and must not contain an authority, user information, `@`, backslashes, a query or a fragment. A complete URL is not accepted as `TokenEndpoint`.

### Optional OIDC Discovery
`ClientCredentialsWithDiscovery` reads `token_endpoint` from the tenant's `/.well-known/openid-configuration`. This method accepts additional form parameters, but no endpoint-path override.

```go
encodedToken, err := tokenFlows.ClientCredentialsWithDiscovery(ctx, customerTenantUrl, params)
```

Pass `config.GetURL()` as `customerTenantUrl` to use the bound tenant, or a trusted subscriber tenant URL for a customer-specific token.

### URL and HTTP Client Requirements
Both methods require an HTTPS tenant URL without user information, a query or a fragment. The path must be empty or `/`. Bare hosts and protocol-relative URLs are not accepted.

The tenant host must match `identity.GetDomains()` exactly or have one additional subdomain consisting of 1–63 letters, digits or hyphens. Ports are part of this comparison: an explicit port, including `:443`, is only accepted when the corresponding domain and port are configured as trusted.

The discovered `token_endpoint` must also use HTTPS, contain no user information or fragment, and match the same trusted-domain rules. It may belong to another trusted tenant host; it is not restricted to the discovery origin.

Token, discovery and JWKS requests do not follow redirects, including when a custom `Options.HTTPClient` is supplied. The supplied client is not modified. Discovery uses the caller's context and omits client certificates when using Go's standard `*http.Transport`. Custom round trippers and TLS dialers remain responsible for their own authentication behavior.

## Cache

`TokenFlows` caches tokens internally. The discovery method also caches the discovered token endpoint per tenant host.

