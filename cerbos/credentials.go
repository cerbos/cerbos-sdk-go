// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"
	"encoding/base64"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

type basicAuthCredentials struct {
	headerVal  string
	requireTLS bool
}

// newBasicAuthCredentials creates a new grpc PerRPCCredentials object that uses basic auth.
func newBasicAuthCredentials(username, password string) basicAuthCredentials {
	auth := username + ":" + password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))

	return basicAuthCredentials{headerVal: "Basic " + enc, requireTLS: true}
}

// Insecure relaxes the TLS requirement for using the credential.
func (ba basicAuthCredentials) Insecure() basicAuthCredentials {
	return basicAuthCredentials{headerVal: ba.headerVal, requireTLS: false}
}

func (ba basicAuthCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{internal.AuthorizationHeader: ba.headerVal}, nil
}

func (ba basicAuthCredentials) RequireTransportSecurity() bool {
	return ba.requireTLS
}

type playgroundInstanceCredentials struct {
	instance string
}

func newPlaygroundInstanceCredentials(instance string) playgroundInstanceCredentials {
	return playgroundInstanceCredentials{instance: instance}
}

func (pic playgroundInstanceCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{internal.PlaygroundInstanceHeader: pic.instance}, nil
}

func (playgroundInstanceCredentials) RequireTransportSecurity() bool {
	return false
}
