// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"
	"fmt"
	"slices"

	"github.com/cerbos/cerbos-sdk-go/internal"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

const checkResourcesBatchSizeLimit = 50

// BatchingAdapter wraps a GRPCClient and automatically splits CheckResources
// calls into multiple batches when the number of resources exceeds the batch size limit.
// CerbosCallId in the returned CheckResourcesResponse is a pipe (“|”) delimited
// concatenation of the CerbosCallId from each batch.
type BatchingAdapter struct {
	*GRPCClient
}

var _ Client[*BatchingAdapter, *BatchingPrincipalCtx] = (*BatchingAdapter)(nil)

// NewBatchingAdapter creates a new BatchingAdapter that wraps the given GRPCClient.
func NewBatchingAdapter(client *GRPCClient) *BatchingAdapter {
	return &BatchingAdapter{GRPCClient: client}
}

func (ba *BatchingAdapter) With(reqOpts ...RequestOpt) *BatchingAdapter {
	return &BatchingAdapter{GRPCClient: ba.GRPCClient.With(reqOpts...)}
}

func (ba *BatchingAdapter) WithPrincipal(p *Principal) *BatchingPrincipalCtx {
	return &BatchingPrincipalCtx{client: ba, principal: p}
}

func (ba *BatchingAdapter) CheckResources(ctx context.Context, principal *Principal, resourceBatch *ResourceBatch) (*CheckResourcesResponse, error) {
	if ba.opts.ShouldValidate() {
		if err := internal.IsValid(principal); err != nil {
			return nil, fmt.Errorf("invalid principal: %w", err)
		}

		if err := internal.IsValid(resourceBatch); err != nil {
			return nil, fmt.Errorf("invalid resource batch; %w", err)
		}
	}

	requestID := ba.opts.RequestID(ctx)
	checkResponseProto := &responsev1.CheckResourcesResponse{
		RequestId: requestID,
		Results:   make([]*responsev1.CheckResourcesResponse_ResultEntry, 0, len(resourceBatch.Batch)),
	}

	for batch := range slices.Chunk(resourceBatch.Batch, checkResourcesBatchSizeLimit) {
		req := &requestv1.CheckResourcesRequest{
			RequestId: requestID,
			Principal: principal.Obj,
			Resources: batch,
		}

		if ba.opts != nil {
			req.AuxData = ba.opts.AuxData
			req.IncludeMeta = ba.opts.IncludeMeta
			req.RequestContext = ba.opts.RequestContext
		}

		resp, err := ba.stub.CheckResources(ba.opts.Context(ctx), req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}

		if checkResponseProto.CerbosCallId == "" {
			checkResponseProto.CerbosCallId = resp.CerbosCallId
		} else {
			checkResponseProto.CerbosCallId = checkResponseProto.CerbosCallId + "|" + resp.CerbosCallId
		}
		checkResponseProto.Results = append(checkResponseProto.Results, resp.Results...)
	}

	return &CheckResourcesResponse{CheckResourcesResponse: checkResponseProto}, nil
}

// BatchingPrincipalCtx provides convenience methods to access the Cerbos API
// in the context of a single principal, with automatic batching for CheckResources.
type BatchingPrincipalCtx struct {
	client    *BatchingAdapter
	principal *Principal
}

func (pc BatchingPrincipalCtx) Principal() *Principal {
	return pc.principal
}

func (pc BatchingPrincipalCtx) IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error) {
	return pc.client.IsAllowed(ctx, pc.principal, resource, action)
}

func (pc BatchingPrincipalCtx) CheckResources(ctx context.Context, batch *ResourceBatch) (*CheckResourcesResponse, error) {
	return pc.client.CheckResources(ctx, pc.principal, batch)
}

func (pc BatchingPrincipalCtx) PlanResources(ctx context.Context, resource *Resource, actions ...string) (*PlanResourcesResponse, error) {
	return pc.client.PlanResources(ctx, pc.principal, resource, actions...)
}
