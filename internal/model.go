// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"

	"google.golang.org/grpc/metadata"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

type ReqOpt struct {
	AuxData     *requestv1.AuxData
	Metadata    metadata.MD
	IncludeMeta bool
}

func (o *ReqOpt) Context(ctx context.Context) context.Context {
	if o == nil || len(o.Metadata) == 0 {
		return ctx
	}

	return metadata.NewOutgoingContext(ctx, o.Metadata)
}
