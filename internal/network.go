// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"crypto/tls"
	"fmt"
	"runtime"
	"runtime/debug"
)

func DefaultTLSConfig() *tls.Config {
	// See https://wiki.mozilla.org/Security/Server_Side_TLS
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2"},
	}
}

func UserAgent(impl string) string {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/cerbos/cerbos-sdk-go" {
				version = dep.Version
				break
			}
		}
	}

	return fmt.Sprintf("cerbos-sdk-go/%s-%s (%s; %s)", impl, version, runtime.GOOS, runtime.GOARCH)
}
