// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"context"
	"errors"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

var (
	_ cerbos.Client[*Adapter, *PrincipalCtx] = (*Adapter)(nil)

	// ErrNotImplemented is returned when a method is not supported by the AuthZEN adapter.
	ErrNotImplemented = errors.New("not implemented")
)

// Adapter implements the cerbos.Client interface using the AuthZEN HTTP client.
// This allows using AuthZEN as a drop-in replacement for the Cerbos gRPC client.
type Adapter struct {
	client *Client
	opts   *internal.ReqOpt
}

// PrincipalCtx provides a principal-scoped context for the adapter.
type PrincipalCtx struct {
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

	authzenCtx := NewContext()
	authzenCtx.WithIncludeMeta(true)
	authzenCtx.WithRequestID(a.opts.RequestID(ctx))
	if a.opts != nil && a.opts.AuxData != nil {
		auxDataMap := make(map[string]any)
		if jwt := a.opts.AuxData.GetJwt(); jwt != nil {
			auxDataMap["jwt"] = map[string]any{
				"token":    jwt.Token,
				"keySetId": jwt.KeySetId,
			}
		}
		authzenCtx.WithAuxData(auxDataMap)
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

	defaultContext := NewContext()
	defaultContext.WithIncludeMeta(true)
	defaultContext.WithRequestID(a.opts.RequestID(ctx))
	if a.opts != nil && a.opts.AuxData != nil {
		auxDataMap := make(map[string]any)
		if jwt := a.opts.AuxData.GetJwt(); jwt != nil {
			auxDataMap["jwt"] = map[string]any{
				"token":    jwt.Token,
				"keySetId": jwt.KeySetId,
			}
		}
		defaultContext.WithAuxData(auxDataMap)
	}

	batchReq := &BatchEvaluationRequest{
		DefaultSubject: subject,
		DefaultContext: defaultContext,
		Evaluations:    make([]BatchEvaluation, 0),
		Semantics:      ExecuteAll,
	}

	// Convert each resource check to a batch evaluation
	for _, entry := range resources.Batch {
		// Wrap protobuf Resource in cerbos.Resource for conversion
		resource := &cerbos.Resource{Obj: entry.Resource}
		authzenResource, err := FromCerbosResource(resource)
		if err != nil {
			return nil, fmt.Errorf("failed to convert resource %q: %w", entry.Resource.Id, err)
		}

		// Create an evaluation for each action
		for _, action := range entry.Actions {
			batchReq.Evaluations = append(batchReq.Evaluations, BatchEvaluation{
				Resource: authzenResource,
				Action:   NewAction(action),
			})
		}
	}

	result, err := a.client.AccessEvaluations(ctx, batchReq)
	if err != nil {
		return nil, fmt.Errorf("batch evaluation failed: %w", err)
	}

	return a.convertBatchResults(result)
}

func (a *Adapter) convertBatchResults(result *AccessEvaluationBatchResult) (*cerbos.CheckResourcesResponse, error) {
	resp := new(cerbos.CheckResourcesResponse)
	resp.Results = make([]*responsev1.CheckResourcesResponse_ResultEntry, result.Count())

	for i := range result.GetEvaluations() {
		firstResult := &AccessEvaluationResult{
			AccessEvaluationResponse: result.GetEvaluations()[i],
		}

		// Get the Cerbos response which includes full metadata
		cerbosResp, err := firstResult.GetCerbosResponse()
		if err != nil {
			return nil, fmt.Errorf("failed to extract Cerbos response from AuthZEN batch result: %w", err)
		}
		resp.Results[i] = 
	}

	return resp, nil
}

// ServerInfo retrieves server information.
// Note: AuthZEN doesn't have a direct equivalent, so we return minimal information.
func (a *Adapter) ServerInfo(ctx context.Context) (*cerbos.ServerInfo, error) {
	return &cerbos.ServerInfo{
		ServerInfoResponse: &responsev1.ServerInfoResponse{
			Version:   "authzen", // AuthZEN doesn't provide version info
			Commit:    "",
			BuildDate: "",
		},
	}, nil
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
func (a *Adapter) PlanResources(ctx context.Context, principal *cerbos.Principal, resource *cerbos.Resource, actions ...string) (*cerbos.PlanResourcesResponse, error) {
	return nil, fmt.Errorf("PlanResources: %w", ErrNotImplemented)
}

// WithPrincipal creates a principal-scoped context.
func (a *Adapter) WithPrincipal(principal *cerbos.Principal) *PrincipalCtx {
	return &PrincipalCtx{
		adapter:   a,
		principal: principal,
	}
}

// Principal returns the principal attached to this context.
func (pc *PrincipalCtx) Principal() *cerbos.Principal {
	return pc.principal
}

// IsAllowed checks if the principal is allowed to perform an action on a resource.
func (pc *PrincipalCtx) IsAllowed(ctx context.Context, resource *cerbos.Resource, action string) (bool, error) {
	return pc.adapter.IsAllowed(ctx, pc.principal, resource, action)
}

// CheckResources checks access to a batch of resources for the principal.
func (pc *PrincipalCtx) CheckResources(ctx context.Context, resources *cerbos.ResourceBatch) (*cerbos.CheckResourcesResponse, error) {
	return pc.adapter.CheckResources(ctx, pc.principal, resources)
}

// PlanResources is not supported by the AuthZEN adapter.
func (pc *PrincipalCtx) PlanResources(ctx context.Context, resource *cerbos.Resource, actions ...string) (*cerbos.PlanResourcesResponse, error) {
	return pc.adapter.PlanResources(ctx, pc.principal, resource, actions...)
}
