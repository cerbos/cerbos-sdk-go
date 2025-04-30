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

// ModifyFiles applies the given set of file modifications to the remote store, returning the new store version on success.
// If the call doesn't modify the remote store (e.g. if the same request was sent twice in a row), it returns an error indicating that the operation was discarded.
func (sc *StoreClient) ModifyFiles(ctx context.Context, req *ModifyFilesRequest) (int64, error) {
	if err := req.Validate(); err != nil {
		return 0, fmt.Errorf("invalid request: %w", err)
	}

	resp, err := sc.client.ModifyFiles(ctx, req.Proto())
	if err != nil {
		return 0, err
	}

	return resp.GetNewStoreVersion(), nil
}

// ModifyFilesLenient applies the given set of file modifications to the remote store, returning the new store version on success.
// Unlike the `ModifyFiles` method, this method ignores the error from the backend when the call doesn't modify the store state. The returned store version would be 0 in that case.
func (sc *StoreClient) ModifyFilesLenient(ctx context.Context, req *ModifyFilesRequest) (int64, error) {
	version, err := sc.ModifyFiles(ctx, req)
	if err != nil {
		rpcErr := new(StoreRPCError)
		if errors.As(err, rpcErr) && rpcErr.Kind == store.RPCErrorOperaionDiscarded {
			return version, nil
		}
	}

	return version, err
}
