// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"google.golang.org/grpc/metadata"

	"github.com/cerbos/cerbos-sdk-go/internal"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

// RequestOpt defines per-request options.
type RequestOpt func(*internal.ReqOpt)

// AuxDataJWT sets the JWT to be used as auxiliary data for the request.
func AuxDataJWT(token, keySetID string) RequestOpt {
	return func(opts *internal.ReqOpt) {
		if opts.AuxData == nil {
			opts.AuxData = &requestv1.AuxData{}
		}

		if opts.AuxData.Jwt == nil {
			opts.AuxData.Jwt = &requestv1.AuxData_JWT{}
		}

		opts.AuxData.Jwt.Token = token
		opts.AuxData.Jwt.KeySetId = keySetID
	}
}

// IncludeMeta sets the flag on requests that support it to signal that evaluation metadata should be sent back with the response.
func IncludeMeta(f bool) RequestOpt {
	return func(opt *internal.ReqOpt) {
		opt.IncludeMeta = f
	}
}

// Headers sets the gRPC header metadata for each request.
// Input should be a list of key-value pairs.
func Headers(keyValues ...string) RequestOpt {
	return func(opt *internal.ReqOpt) {
		opt.Metadata = metadata.Pairs(keyValues...)
	}
}
