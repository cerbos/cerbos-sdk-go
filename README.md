![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos-sdk-go?color=green&logo=github&sort=semver) [![Go Reference](https://pkg.go.dev/badge/github.com/cerbos/cerbos-sdk-go/client.svg)](https://pkg.go.dev/github.com/cerbos/cerbos-sdk-go)

# Cerbos Client SDK for Go

```
go get github.com/cerbos/cerbos-sdk-go
```

The Go client SDK is an easy way to implement access controls in your own applications by communicating with the Cerbos PDP. Whether Cerbos runs as a [microservice or a sidecar](https://docs.cerbos.dev/cerbos/deployment/index.html), the client SDK is able to communicate with the PDP using TCP or Unix domain sockets.

See Go docs for more information.

## Check Access


```go
c, err := cerbos.New("unix:/var/sock/cerbos", cerbos.WithTLSCACert("/path/to/ca.crt"))
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}

allowed, err := c.IsAllowed(
    context.TODO(),
    cerbos.NewPrincipal("sally").WithRoles("user"),
    cerbos.NewResource("album:object", "A001"),
    "view",
)
if err != nil {
    log.Fatalf("Failed to check permission: %v", err)
}

log.Printf("Is Sally allowed to view album A001: %t", allowed)
```

## Migrating from github.com/cerbos/cerbos/client

This project supersedes the Cerbos Go client available at `github.com/cerbos/cerbos/client`. The new SDK has fewer dependencies and a release cycle that's not tied to the main Cerbos project. Going forward, new features and enhancements will only be added to this project.

Migrating most of the existing code should be just a matter of renaming the package imports.

- Change import paths from `github.com/cerbos/cerbos/client` to `github.com/cerbos/cerbos-sdk-go/cerbos`. Optionally, alias the new import as `client "github.com/cerbos/cerbos-sdk-go/cerbos` to avoid having to change package references in code.
- Deprecated RPCs (`CheckResourceSet`, `CheckResourceBatch`) have been removed from the new client implementation
- The process for starting a Cerbos test server has changed in order to avoid pulling in dependencies of the Cerbos project. Use the `NewCerbosServerLauncher` function from `github.com/cerbos/cerbos-sdk-go/testutil` to create a launcher and call the `Launch()` method to start a Cerbos container. Refer to Go docs for details.
