// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"

	"github.com/cerbos/cloud-api/store"
)

type StoreRPCError = store.RPCError

type StoreClient struct {
	client *store.Client
}

func NewStoreClient(client *store.Client) *StoreClient {
	return &StoreClient{client: client}
}

// ReplaceFiles overwrites the store so that it only contains the valid files included in the request.
func (sc *StoreClient) ReplaceFiles(ctx context.Context, req *ReplaceFilesRequest) (*ReplaceFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	resp, err := sc.client.ReplaceFiles(ctx, req.Obj)
	if err != nil {
		return nil, err
	}

	return &ReplaceFilesResponse{ReplaceFilesResponse: resp}, nil
}

// ReplaceFilesLenient overwrites the store so that it only contains the valid files included in the request.
// This method ignores the error from the backend when the call doesn't make a discernible change to the store to create a new version. The returned response would be nil in that case.
func (sc *StoreClient) ReplaceFilesLenient(ctx context.Context, req *ReplaceFilesRequest) (*ReplaceFilesResponse, error) {
	resp, err := sc.ReplaceFiles(ctx, req)
	if err != nil {
		rpcErr := new(StoreRPCError)
		if errors.As(err, rpcErr) && rpcErr.Kind == store.RPCErrorOperaionDiscarded {
			return nil, nil
		}
	}

	return resp, err
}

// ModifyFiles applies the given set of file modifications to the remote store.
// If the call doesn't modify the remote store (e.g. if the same request was sent twice in a row), it returns an error indicating that the operation was discarded.
func (sc *StoreClient) ModifyFiles(ctx context.Context, req *ModifyFilesRequest) (*ModifyFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	resp, err := sc.client.ModifyFiles(ctx, req.Proto())
	if err != nil {
		return nil, err
	}

	return &ModifyFilesResponse{ModifyFilesResponse: resp}, nil
}

// ModifyFilesLenient applies the given set of file modifications to the remote store.
// This method ignores the error from the backend when the call doesn't make a discernible change to the store to create a new version. The returned response would be nil in that case.
func (sc *StoreClient) ModifyFilesLenient(ctx context.Context, req *ModifyFilesRequest) (*ModifyFilesResponse, error) {
	resp, err := sc.ModifyFiles(ctx, req)
	if err != nil {
		rpcErr := new(StoreRPCError)
		if errors.As(err, rpcErr) && rpcErr.Kind == store.RPCErrorOperaionDiscarded {
			return nil, nil
		}
	}

	return resp, err
}
