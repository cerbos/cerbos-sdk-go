// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"context"
	"errors"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal"
)

var (
	_ cerbos.Client[*Adapter, *PrincipalCtxAdapter] = (*Adapter)(nil)

	// ErrNotImplemented is returned when a method is not supported by the AuthZEN adapter.
	ErrNotImplemented = errors.New("not implemented")
)

// Adapter implements the cerbos.Client interface using the AuthZEN HTTP client.
// This allows using AuthZEN as a drop-in replacement for the Cerbos gRPC client.
type Adapter struct {
	client *Client
	opts   *internal.ReqOpt
}

// PrincipalCtxAdapter provides a principal-scoped context for the adapter.
type PrincipalCtxAdapter struct {
	adapter   *Adapter
	principal *cerbos.Principal
}

// NewAdapter creates a new Cerbos client adapter that uses AuthZEN HTTP protocol.
// The baseURL should be the full URL to the Cerbos server (e.g., "https://localhost:3592").
func NewAdapter(baseURL string, opts ...Opt) (*Adapter, error) {
	client, err := NewClient(baseURL, opts...)
	if err != nil {
		return nil, err
	}

	return &Adapter{
		client: client,
		opts:   &internal.ReqOpt{},
	}, nil
}

// NewGRPCAdapter creates a new Cerbos client adapter that uses AuthZEN API over GRPC protocol.
func NewGRPCAdapter(address string, opts ...cerbos.Opt) (*Adapter, error) {
	client, err := NewGRPCClient(address, opts...)
	if err != nil {
		return nil, err
	}

	return &Adapter{
		client: client,
		opts:   &internal.ReqOpt{},
	}, nil
}

// IsAllowed checks if a principal is allowed to perform an action on a resource.
func (a *Adapter) IsAllowed(ctx context.Context, principal *cerbos.Principal, resource *cerbos.Resource, action string) (bool, error) {
	subject, err := FromCerbosPrincipal(principal)
	if err != nil {
		return false, fmt.Errorf("failed to convert principal: %w", err)
	}

	authzenResource, err := FromCerbosResource(resource)
	if err != nil {
		return false, fmt.Errorf("failed to convert resource: %w", err)
	}

	authzenAction := NewAction(action)

	authzenCtx := NewContext().
		WithIncludeMeta(true).
		WithRequestID(a.opts.RequestID(ctx))

	if a.opts != nil && a.opts.AuxData != nil {
		authzenCtx.WithAuxData(a.opts.AuxData)
	}

	// Make the AuthZEN request
	result, err := a.client.AccessEvaluation(ctx, subject, authzenResource, authzenAction, authzenCtx)
	if err != nil {
		return false, fmt.Errorf("access evaluation failed: %w", err)
	}

	return result.IsAllowed(), nil
}

func (a *Adapter) CheckResources(ctx context.Context, principal *cerbos.Principal, resources *cerbos.ResourceBatch) (*cerbos.CheckResourcesResponse, error) {
	subject, err := FromCerbosPrincipal(principal)
	if err != nil {
		return nil, fmt.Errorf("failed to convert principal: %w", err)
	}

	defaultContext := NewContext().
		WithIncludeMeta(true).
		WithRequestID(a.opts.RequestID(ctx))

	if a.opts != nil && a.opts.AuxData != nil {
		defaultContext.WithAuxData(a.opts.AuxData)
	}

	batchReq := &BatchEvaluationRequest{
		DefaultSubject: subject,
		DefaultContext: defaultContext,
		Evaluations:    make([]BatchEvaluation, 0),
		Semantics:      ExecuteAll,
	}

	for _, entry := range resources.Batch {
		resource := &cerbos.Resource{Obj: entry.Resource}
		authzenResource, err := FromCerbosResource(resource)
		if err != nil {
			return nil, fmt.Errorf("failed to convert resource %q: %w", entry.Resource.Id, err)
		}

		for _, action := range entry.Actions {
			batchReq.Evaluations = append(batchReq.Evaluations, BatchEvaluation{
				Resource: authzenResource,
				Action:   NewAction(action),
			})
		}
	}
	results, err := a.client.AccessEvaluations(ctx, batchReq)
	if err != nil {
		return nil, fmt.Errorf("batch evaluation failed: %w", err)
	}
	result0, err := results.GetEvaluation(0)
	if err != nil {
		return nil, fmt.Errorf("no corresponding evaluation result: %w", err)
	}
	resp, err := result0.GetCerbosResponse()
	if err != nil {
		return nil, err
	}
	return &cerbos.CheckResourcesResponse{
		CheckResourcesResponse: resp,
	}, nil
}

func (a *Adapter) ServerInfo(_ context.Context) (*cerbos.ServerInfo, error) {
	return nil, fmt.Errorf("ServerInfo: %w", ErrNotImplemented)
}

// With creates a new adapter instance with the given request options.
func (a *Adapter) With(opts ...cerbos.RequestOpt) *Adapter {
	newOpts := &internal.ReqOpt{}
	if a.opts != nil {
		*newOpts = *a.opts
	}

	for _, opt := range opts {
		opt(newOpts)
	}

	return &Adapter{
		client: a.client,
		opts:   newOpts,
	}
}

// PlanResources is not supported by the AuthZEN adapter.
// AuthZEN focuses on access evaluation rather than query planning.
// Returns ErrNotImplemented which tests can check for using errors.Is().
func (a *Adapter) PlanResources(_ context.Context, _ *cerbos.Principal, _ *cerbos.Resource, _ ...string) (*cerbos.PlanResourcesResponse, error) {
	return nil, fmt.Errorf("PlanResources: %w", ErrNotImplemented)
}

// WithPrincipal creates a principal-scoped context.
func (a *Adapter) WithPrincipal(principal *cerbos.Principal) *PrincipalCtxAdapter {
	return &PrincipalCtxAdapter{
		adapter:   a,
		principal: principal,
	}
}

// Principal returns the principal attached to this context.
func (pc *PrincipalCtxAdapter) Principal() *cerbos.Principal {
	return pc.principal
}

// IsAllowed checks if the principal is allowed to perform an action on a resource.
func (pc *PrincipalCtxAdapter) IsAllowed(ctx context.Context, resource *cerbos.Resource, action string) (bool, error) {
	return pc.adapter.IsAllowed(ctx, pc.principal, resource, action)
}

// CheckResources checks access to a batch of resources for the principal.
func (pc *PrincipalCtxAdapter) CheckResources(ctx context.Context, resources *cerbos.ResourceBatch) (*cerbos.CheckResourcesResponse, error) {
	return pc.adapter.CheckResources(ctx, pc.principal, resources)
}

// PlanResources is not supported by the AuthZEN adapter.
func (pc *PrincipalCtxAdapter) PlanResources(ctx context.Context, resource *cerbos.Resource, actions ...string) (*cerbos.PlanResourcesResponse, error) {
	return pc.adapter.PlanResources(ctx, pc.principal, resource, actions...)
}
