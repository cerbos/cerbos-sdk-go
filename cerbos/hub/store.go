// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"

	"buf.build/go/protovalidate"

	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/cerbos/cloud-api/store"
)

type StoreRPCError = store.RPCError

type StoreClient struct {
	client *store.Client
}

type InvalidRequestError struct {
	underlying error
	Violations []*protovalidate.Violation
}

func newInvalidRequestError(err error) InvalidRequestError {
	verr := new(protovalidate.ValidationError)
	if !errors.As(err, &verr) {
		return InvalidRequestError{underlying: err}
	}

	return InvalidRequestError{underlying: err, Violations: verr.Violations}
}

func (ire InvalidRequestError) Error() string {
	return ire.underlying.Error()
}

func (ire InvalidRequestError) Unwrap() error {
	return ire.underlying
}

func NewStoreClient(client *store.Client) *StoreClient {
	return &StoreClient{client: client}
}

// ReplaceFiles overwrites the store so that it only contains the valid files included in the request.
// If the call doesn't modify the remote store (e.g. if the same request was sent twice in a row), it returns an error indicating that the operation was discarded.
func (sc *StoreClient) ReplaceFiles(ctx context.Context, req *ReplaceFilesRequest) (*ReplaceFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, newInvalidRequestError(err)
	}

	resp, err := sc.client.ReplaceFiles(ctx, req.obj)
	if err != nil {
		return nil, err
	}

	return &ReplaceFilesResponse{ReplaceFilesResponse: resp}, nil
}

// ReplaceFilesLenient overwrites the store so that it only contains the valid files included in the request.
// This method ignores the error from the backend when the call doesn't make a discernible change to the store to create a new version.
func (sc *StoreClient) ReplaceFilesLenient(ctx context.Context, req *ReplaceFilesRequest) (*ReplaceFilesResponse, error) {
	resp, err := sc.ReplaceFiles(ctx, req)
	if err != nil {
		rpcErr := new(StoreRPCError)
		if errors.As(err, rpcErr) && rpcErr.Kind == store.RPCErrorOperationDiscarded {
			return &ReplaceFilesResponse{ReplaceFilesResponse: &storev1.ReplaceFilesResponse{NewStoreVersion: rpcErr.CurrentStoreVersion}}, nil
		}
	}

	return resp, err
}

// ModifyFiles applies the given set of file modifications to the remote store.
// If the call doesn't modify the remote store (e.g. if the same request was sent twice in a row), it returns an error indicating that the operation was discarded.
func (sc *StoreClient) ModifyFiles(ctx context.Context, req *ModifyFilesRequest) (*ModifyFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, newInvalidRequestError(err)
	}

	resp, err := sc.client.ModifyFiles(ctx, req.Proto())
	if err != nil {
		return nil, err
	}

	return &ModifyFilesResponse{ModifyFilesResponse: resp}, nil
}

// ModifyFilesLenient applies the given set of file modifications to the remote store.
// This method ignores the error from the backend when the call doesn't make a discernible change to the store to create a new version.
func (sc *StoreClient) ModifyFilesLenient(ctx context.Context, req *ModifyFilesRequest) (*ModifyFilesResponse, error) {
	resp, err := sc.ModifyFiles(ctx, req)
	if err != nil {
		rpcErr := new(StoreRPCError)
		if errors.As(err, rpcErr) && rpcErr.Kind == store.RPCErrorOperationDiscarded {
			return &ModifyFilesResponse{ModifyFilesResponse: &storev1.ModifyFilesResponse{NewStoreVersion: rpcErr.CurrentStoreVersion}}, nil
		}
	}

	return resp, err
}

// ListFiles returns the list of file paths currently available in the store.
func (sc *StoreClient) ListFiles(ctx context.Context, req *ListFilesRequest) (*ListFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, newInvalidRequestError(err)
	}

	resp, err := sc.client.ListFiles(ctx, req.Proto())
	if err != nil {
		return nil, err
	}

	return &ListFilesResponse{ListFilesResponse: resp}, nil
}

func (sc *StoreClient) GetCurrentVersion(ctx context.Context, req *GetCurrentVersionRequest) (*GetCurrentVersionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, newInvalidRequestError(err)
	}

	resp, err := sc.client.GetCurrentVersion(ctx, req.Proto())
	if err != nil {
		return nil, err
	}

	return &GetCurrentVersionResponse{GetCurrentVersionResponse: resp}, nil
}

func (sc *StoreClient) GetFiles(ctx context.Context, req *GetFilesRequest) (*GetFilesResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, newInvalidRequestError(err)
	}

	resp, err := sc.client.GetFiles(ctx, req.Proto())
	if err != nil {
		return nil, err
	}

	return &GetFilesResponse{GetFilesResponse: resp}, nil
}
