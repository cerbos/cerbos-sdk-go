// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"context"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

var _ cerbos.Client[*Adapter, *PrincipalCtx] = (*Adapter)(nil)

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
	// Convert Cerbos types to AuthZEN types
	subject, err := FromCerbosPrincipal(principal)
	if err != nil {
		return false, fmt.Errorf("failed to convert principal: %w", err)
	}

	authzenResource, err := FromCerbosResource(resource)
	if err != nil {
		return false, fmt.Errorf("failed to convert resource: %w", err)
	}

	authzenAction := FromCerbosAction(action)

	// Create AuthZEN context from request options
	var authzenCtx *Context
	if a.opts != nil && (a.opts.RequestIDGenerator != nil || a.opts.IncludeMeta) {
		authzenCtx = NewContext()
		if a.opts.RequestIDGenerator != nil {
			authzenCtx.WithRequestID(a.opts.RequestID(ctx))
		}
		if a.opts.IncludeMeta {
			authzenCtx.WithIncludeMeta(true)
		}
	}

	// Make the AuthZEN request
	result, err := a.client.AccessEvaluation(ctx, subject, authzenResource, authzenAction, authzenCtx)
	if err != nil {
		return false, fmt.Errorf("access evaluation failed: %w", err)
	}

	return result.IsAllowed(), nil
}

// CheckResources checks access to a batch of resources.
func (a *Adapter) CheckResources(ctx context.Context, principal *cerbos.Principal, resources *cerbos.ResourceBatch) (*cerbos.CheckResourcesResponse, error) {
	// Convert principal
	subject, err := FromCerbosPrincipal(principal)
	if err != nil {
		return nil, fmt.Errorf("failed to convert principal: %w", err)
	}

	// Build batch request
	batchReq := &BatchEvaluationRequest{
		DefaultSubject: subject,
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
				Action:   FromCerbosAction(action),
			})
		}
	}

	// Execute batch request
	result, err := a.client.AccessEvaluations(ctx, batchReq)
	if err != nil {
		return nil, fmt.Errorf("batch evaluation failed: %w", err)
	}

	// Convert AuthZEN batch results back to Cerbos CheckResourcesResponse
	return a.convertBatchResults(resources, result)
}

// convertBatchResults converts AuthZEN batch results to Cerbos CheckResourcesResponse.
func (a *Adapter) convertBatchResults(originalBatch *cerbos.ResourceBatch, result *AccessEvaluationBatchResult) (*cerbos.CheckResourcesResponse, error) {
	requestId := ""
	if len(result.Evaluations) >0 {
		requestId := result.Evaluations[0].GetContext()
	}
	response := &cerbos.CheckResourcesResponse{
		CheckResourcesResponse: &responsev1.CheckResourcesResponse{
			RequestId: result.AccessEvaluationBatchResponse.
			Results:   make([]*responsev1.CheckResourcesResponse_ResultEntry, 0, len(originalBatch.Batch)),
		},
	}

	resultIdx := 0
	for _, entry := range originalBatch.Batch {
		resResult := &responsev1.CheckResourcesResponse_ResultEntry{
			Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
				Id:            entry.Resource.Id,
				Kind:          entry.Resource.Kind,
				PolicyVersion: entry.Resource.PolicyVersion,
				Scope:         entry.Resource.Scope,
			},
			Actions: make(map[string]effectv1.Effect, len(entry.Actions)),
		}

		// Map each action result
		for _, action := range entry.Actions {
			if resultIdx < result.Count() {
				decision := result.GetEvaluations()[resultIdx].GetDecision()
				if decision {
					resResult.Actions[action] = effectv1.Effect_EFFECT_ALLOW
				} else {
					resResult.Actions[action] = effectv1.Effect_EFFECT_DENY
				}
				resultIdx++
			}
		}

		response.Results = append(response.Results, resResult)
	}

	return response, nil
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
func (a *Adapter) PlanResources(ctx context.Context, principal *cerbos.Principal, resource *cerbos.Resource, actions ...string) (*cerbos.PlanResourcesResponse, error) {
	return nil, fmt.Errorf("PlanResources is not supported by AuthZEN adapter")
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
