// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"

	"google.golang.org/grpc/metadata"

	"github.com/rs/xid"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

type ReqOpt struct {
	AuxData              *requestv1.AuxData
	Metadata             metadata.MD
	RequestIDGenerator   func(context.Context) string
	RequestContext       *auditv1.RequestContext
	IncludeMeta          bool
	AllowPartialRequests bool
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

func (o *ReqOpt) ShouldValidate() bool {
	return o == nil || !o.AllowPartialRequests
}
