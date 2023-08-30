![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos-sdk-go?color=green&logo=github&sort=semver) [![Go Reference](https://pkg.go.dev/badge/github.com/cerbos/cerbos-sdk-go/client.svg)](https://pkg.go.dev/github.com/cerbos/cerbos-sdk-go/client)

Cerbos Client SDK for Go
========================

```
go get github.com/cerbos/cerbos-sdk-go
```

The Go client SDK is an easy way to implement access controls in your own applications by communicating with the Cerbos PDP. Whether Cerbos runs as a [microservice or a sidecar](https://docs.cerbos.dev/cerbos/deployment/index.html), the client SDK is able to communicate with the PDP using TCP or Unix domain sockets.

See Go docs for more information.

Check Access
------------


```go
c, err := client.New("unix:/var/sock/cerbos", client.WithTLSCACert("/path/to/ca.crt"))
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}

allowed, err := c.IsAllowed(
    context.TODO(),
    client.NewPrincipal("sally").WithRoles("user"),
    client.NewResource("album:object", "A001"),
    "view",
)
if err != nil {
    log.Fatalf("Failed to check permission: %v", err)
}

log.Printf("Is Sally allowed to view album A001: %t", allowed)
```

