// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"

	"google.golang.org/grpc/metadata"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/rs/xid"
)

type ReqOpt struct {
	AuxData            *requestv1.AuxData
	Metadata           metadata.MD
	RequestIDGenerator func(context.Context) string
	IncludeMeta        bool
}

func (o *ReqOpt) Context(ctx context.Context) context.Context {
	if o == nil || len(o.Metadata) == 0 {
		return ctx
	}

	return metadata.NewOutgoingContext(ctx, o.Metadata)
}

func (o *ReqOpt) RequestID(ctx context.Context) string {
	if o != nil && o.RequestIDGenerator != nil {
		return o.RequestIDGenerator(ctx)
	}

	reqID := xid.New()
	return reqID.String()
}
