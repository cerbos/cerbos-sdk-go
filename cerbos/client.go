// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

// Client provides access to the Cerbos API.
type Client[C any, P PrincipalContext] interface {
	// IsAllowed checks access to a single resource by a principal and returns true if access is granted.
	IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error)
	// CheckResources checks access to a batch of resources of different kinds.
	CheckResources(ctx context.Context, principal *Principal, resources *ResourceBatch) (*CheckResourcesResponse, error)
	// ServerInfo retrieves server information.
	ServerInfo(ctx context.Context) (*ServerInfo, error)
	// With sets per-request options for the client.
	With(opts ...RequestOpt) C
	// PlanResources creates a query plan for performing the given action on a set of resources of the given kind.
	PlanResources(ctx context.Context, principal *Principal, resource *Resource, action string) (*PlanResourcesResponse, error)
	// WithPrincipal sets the principal to be used for subsequent API calls.
	// WithPrincipal sets the principal to be used for subsequent API calls.
	WithPrincipal(principal *Principal) P
}

// PrincipalContext provides convenience methods to access the Cerbos API in the context of a single principal.
type PrincipalContext interface {
	// Principal returns the principal attached to this context.
	Principal() *Principal
	// IsAllowed checks access to a single resource by the principal and returns true if access is granted.
	IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error)
	// CheckResources checks access to a batch of resources of different kinds.
	CheckResources(ctx context.Context, resources *ResourceBatch) (*CheckResourcesResponse, error)
	// PlanResources creates a query plan for performing the given action on a set of resources of the given kind.
	PlanResources(ctx context.Context, resource *Resource, action string) (*PlanResourcesResponse, error)
}

// AdminClient provides access to the Cerbos Admin API.
type AdminClient interface {
	AddOrUpdatePolicy(ctx context.Context, policies *PolicySet) error
	AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error)
	ListPolicies(ctx context.Context, opts ...ListPoliciesOption) ([]string, error)
	InspectPolicies(ctx context.Context, opts ...InspectPoliciesOption) (*responsev1.InspectPoliciesResponse, error)
	GetPolicy(ctx context.Context, ids ...string) ([]*policyv1.Policy, error)
	DisablePolicy(ctx context.Context, ids ...string) (uint32, error)
	EnablePolicy(ctx context.Context, ids ...string) (uint32, error)
	AddOrUpdateSchema(ctx context.Context, schemas *SchemaSet) error
	DeleteSchema(ctx context.Context, ids ...string) (uint32, error)
	ListSchemas(ctx context.Context) ([]string, error)
	GetSchema(ctx context.Context, ids ...string) ([]*schemav1.Schema, error)
	ReloadStore(ctx context.Context, wait bool) error
}
