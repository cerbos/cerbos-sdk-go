// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
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
	PlanResources(ctx context.Context, principal *Principal, resource *Resource, actions ...string) (*PlanResourcesResponse, error)
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
	PlanResources(ctx context.Context, resource *Resource, actions ...string) (*PlanResourcesResponse, error)
}

// AdminClient provides access to the Cerbos Admin API.
type AdminClient interface {
	AddOrUpdatePolicy(ctx context.Context, policies *PolicySet) error
	AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error)
	ListPolicies(ctx context.Context, opts ...FilterOption) ([]string, error)
	InspectPolicies(ctx context.Context, opts ...FilterOption) (*responsev1.InspectPoliciesResponse, error)
	GetPolicy(ctx context.Context, ids ...string) ([]*policyv1.Policy, error)
	DeletePolicy(ctx context.Context, ids ...string) (uint32, error)
	DisablePolicy(ctx context.Context, ids ...string) (uint32, error)
	EnablePolicy(ctx context.Context, ids ...string) (uint32, error)
	AddOrUpdateSchema(ctx context.Context, schemas *SchemaSet) error
	DeleteSchema(ctx context.Context, ids ...string) (uint32, error)
	ListSchemas(ctx context.Context) ([]string, error)
	GetSchema(ctx context.Context, ids ...string) ([]*schemav1.Schema, error)
	PurgeStoreRevisions(ctx context.Context, keepLast uint32) (uint32, error)
	ReloadStore(ctx context.Context, wait bool) error
}

// Hub provides access to Cerbos Hub APIs.
type Hub[S HubStoreClient] interface {
	StoreClient() S
}

// HubStoreClient provides access to the Cerbos Hub store API.
type HubStoreClient interface {
	ReplaceFiles(context.Context, *hub.ReplaceFilesRequest) (*hub.ReplaceFilesResponse, error)
	ReplaceFilesLenient(context.Context, *hub.ReplaceFilesRequest) (*hub.ReplaceFilesResponse, error)
	ModifyFiles(context.Context, *hub.ModifyFilesRequest) (*hub.ModifyFilesResponse, error)
	ModifyFilesLenient(context.Context, *hub.ModifyFilesRequest) (*hub.ModifyFilesResponse, error)
	ListFiles(context.Context, *hub.ListFilesRequest) (*hub.ListFilesResponse, error)
	GetCurrentVersion(context.Context, *hub.GetCurrentVersionRequest) (*hub.GetCurrentVersionResponse, error)
	GetFiles(context.Context, *hub.GetFilesRequest) (*hub.GetFilesResponse, error)
}

var (
	_ Hub[*hub.StoreClient] = (*HubClient)(nil)
	_ HubStoreClient        = (*hub.StoreClient)(nil)
)
