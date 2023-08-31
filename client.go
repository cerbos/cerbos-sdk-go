// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package cerbossdk provides client implementations to interact with the Cerbos API.
package cerbossdk

import "github.com/cerbos/cerbos-sdk-go/grpcimpl"

// NewClient returns a new client for the Cerbos API.
func NewClient(address string, opts ...grpcimpl.Opt) (*grpcimpl.Client, error) {
	return grpcimpl.New(address, opts...)
}

// NewAdminClient returns a new client for the Cerbos Admin API.
func NewAdminClient(address string, opts ...grpcimpl.Opt) (*grpcimpl.AdminClient, error) {
	return grpcimpl.NewAdminClient(address, opts...)
}

// NewAdminClient returns a new client for the Cerbos Admin API.
func NewAdminClientWithCredentials(address, username, password string, opts ...grpcimpl.Opt) (*grpcimpl.AdminClient, error) {
	return grpcimpl.NewAdminClientWithCredentials(address, username, password, opts...)
}
