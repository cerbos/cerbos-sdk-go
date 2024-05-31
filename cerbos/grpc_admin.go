// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

const (
	addPolicyBatchSize = 10
	addSchemaBatchSize = 10
)

// NewAdminClient creates a new admin client.
// It will look for credentials in the following order:
// - Environment: CERBOS_USERNAME and CERBOS_PASSWORD
// - Netrc file (~/.netrc if an override is not defined in the NETRC environment variable)
//
// Note that Unix domain socket connections cannot fallback to netrc and require either the
// environment variables to be defined or the credentials to provided explicitly via the
// NewAdminClientWithCredentials function.
func NewAdminClient(address string, opts ...Opt) (*GRPCAdminClient, error) {
	return NewAdminClientWithCredentials(address, "", "", opts...)
}

// NewAdminClientWithCredentials creates a new admin client using credentials explicitly passed as arguments.
func NewAdminClientWithCredentials(address, username, password string, opts ...Opt) (*GRPCAdminClient, error) {
	// TODO: handle this in call site
	target, user, pass, err := internal.LoadBasicAuthData(internal.OSEnvironment{}, address, username, password)
	if err != nil {
		return nil, err
	}

	grpcConn, conf, err := mkConn(target, opts...)
	if err != nil {
		return nil, err
	}

	basicAuth := newBasicAuthCredentials(user, pass)
	if conf.plaintext {
		basicAuth = basicAuth.Insecure()
	}

	return &GRPCAdminClient{client: svcv1.NewCerbosAdminServiceClient(grpcConn), creds: basicAuth}, nil
}

type GRPCAdminClient struct {
	client  svcv1.CerbosAdminServiceClient
	creds   credentials.PerRPCCredentials
	headers []string
}

func (c *GRPCAdminClient) WithHeaders(keyValues ...string) *GRPCAdminClient {
	return &GRPCAdminClient{
		client:  c.client,
		creds:   c.creds,
		headers: keyValues,
	}
}

func (c *GRPCAdminClient) AddOrUpdatePolicy(ctx context.Context, policies *PolicySet) error {
	if err := policies.Validate(); err != nil {
		return err
	}

	all := policies.GetPolicies()
	for bs := 0; bs < len(all); bs += addPolicyBatchSize {
		be := bs + addPolicyBatchSize
		if be >= len(all) {
			be = len(all)
		}

		req := &requestv1.AddOrUpdatePolicyRequest{Policies: all[bs:be]}
		if _, err := c.client.AddOrUpdatePolicy(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds)); err != nil {
			return fmt.Errorf("failed to send batch [%d,%d): %w", bs, be, err)
		}
	}

	return nil
}

type recvFn func() (*responsev1.ListAuditLogEntriesResponse, error)

// collectLogs collects logs from the receiver function and passes to the channel
// it will return an error if the channel type is not accepted.
func collectLogs(receiver recvFn) (<-chan *AuditLogEntry, error) {
	ch := make(chan *AuditLogEntry)

	go func() {
		defer close(ch)

		for {
			entry, err := receiver()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}

				ch <- NewAuditLogEntry(nil, nil, err)
				return
			}

			ch <- NewAuditLogEntry(entry.GetAccessLogEntry(), entry.GetDecisionLogEntry(), nil)
		}
	}()

	return ch, nil
}

func (c *GRPCAdminClient) AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error) {
	resp, err := c.auditLogs(ctx, opts)
	if err != nil {
		return nil, err
	}

	return collectLogs(resp.Recv)
}

func (c *GRPCAdminClient) auditLogs(ctx context.Context, opts AuditLogOptions) (svcv1.CerbosAdminService_ListAuditLogEntriesClient, error) {
	var req *requestv1.ListAuditLogEntriesRequest
	switch opts.Type {
	case AccessLogs:
		req = &requestv1.ListAuditLogEntriesRequest{Kind: requestv1.ListAuditLogEntriesRequest_KIND_ACCESS}
	case DecisionLogs:
		req = &requestv1.ListAuditLogEntriesRequest{Kind: requestv1.ListAuditLogEntriesRequest_KIND_DECISION}
	default:
		return nil, errors.New("incorrect audit log type")
	}

	switch {
	case opts.Tail > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Tail{Tail: opts.Tail}
	case !opts.StartTime.IsZero() && !opts.EndTime.IsZero():
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Between{
			Between: &requestv1.ListAuditLogEntriesRequest_TimeRange{
				Start: timestamppb.New(opts.StartTime),
				End:   timestamppb.New(opts.EndTime),
			},
		}
	case opts.Lookup != "":
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Lookup{Lookup: opts.Lookup}
	}

	if err := internal.Validate(req); err != nil {
		return nil, err
	}

	resp, err := c.client.ListAuditLogEntries(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *GRPCAdminClient) ListPolicies(ctx context.Context, opts ...FilterOption) ([]string, error) {
	options := &FilterOptions{}
	for _, opt := range opts {
		opt(options)
	}
	req := &requestv1.ListPoliciesRequest{
		PolicyId:        options.PolicyIDs,
		IncludeDisabled: options.IncludeDisabled,
		NameRegexp:      options.NameRegexp,
		ScopeRegexp:     options.ScopeRegexp,
		VersionRegexp:   options.VersionRegexp,
	}
	if err := internal.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate list policies request: %w", err)
	}

	p, err := c.client.ListPolicies(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not list policies: %w", err)
	}

	return p.PolicyIds, nil
}

func (c *GRPCAdminClient) InspectPolicies(ctx context.Context, opts ...FilterOption) (*responsev1.InspectPoliciesResponse, error) {
	options := &FilterOptions{}
	for _, opt := range opts {
		opt(options)
	}
	req := &requestv1.InspectPoliciesRequest{
		PolicyId:        options.PolicyIDs,
		IncludeDisabled: options.IncludeDisabled,
		NameRegexp:      options.NameRegexp,
		ScopeRegexp:     options.ScopeRegexp,
		VersionRegexp:   options.VersionRegexp,
	}
	if err := internal.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate get inspect policies request: %w", err)
	}

	resp, err := c.client.InspectPolicies(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not inspect policies: %w", err)
	}

	return resp, nil
}

func (c *GRPCAdminClient) GetPolicy(ctx context.Context, ids ...string) ([]*policyv1.Policy, error) {
	req := &requestv1.GetPolicyRequest{
		Id: ids,
	}
	if err := internal.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate get policy request: %w", err)
	}

	res, err := c.client.GetPolicy(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not get policy: %w", err)
	}

	return res.Policies, nil
}

func (c *GRPCAdminClient) DisablePolicy(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.DisablePolicyRequest{
		Id: ids,
	}
	if err := internal.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate disable policy request: %w", err)
	}

	resp, err := c.client.DisablePolicy(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not disable policy: %w", err)
	}

	return resp.DisabledPolicies, nil
}

func (c *GRPCAdminClient) EnablePolicy(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.EnablePolicyRequest{
		Id: ids,
	}
	if err := internal.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate enable policy request: %w", err)
	}

	resp, err := c.client.EnablePolicy(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not enable policy: %w", err)
	}

	return resp.EnabledPolicies, nil
}

func (c *GRPCAdminClient) AddOrUpdateSchema(ctx context.Context, schemas *SchemaSet) error {
	all := schemas.GetSchemas()
	for bs := 0; bs < len(all); bs += addSchemaBatchSize {
		be := bs + addSchemaBatchSize
		if be >= len(all) {
			be = len(all)
		}

		req := &requestv1.AddOrUpdateSchemaRequest{Schemas: all[bs:be]}
		if _, err := c.client.AddOrUpdateSchema(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds)); err != nil {
			return fmt.Errorf("failed to send batch [%d,%d): %w", bs, be, err)
		}
	}

	return nil
}

func (c *GRPCAdminClient) DeleteSchema(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.DeleteSchemaRequest{
		Id: ids,
	}
	if err := internal.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate delete schema request: %w", err)
	}

	resp, err := c.client.DeleteSchema(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not delete schema: %w", err)
	}

	return resp.DeletedSchemas, nil
}

func (c *GRPCAdminClient) ListSchemas(ctx context.Context) ([]string, error) {
	req := &requestv1.ListSchemasRequest{}
	if err := internal.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate list schemas request: %w", err)
	}

	s, err := c.client.ListSchemas(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not list schemas: %w", err)
	}

	return s.SchemaIds, nil
}

func (c *GRPCAdminClient) GetSchema(ctx context.Context, ids ...string) ([]*schemav1.Schema, error) {
	req := &requestv1.GetSchemaRequest{
		Id: ids,
	}
	if err := internal.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate get schema request: %w", err)
	}

	res, err := c.client.GetSchema(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not get schema: %w", err)
	}

	return res.Schemas, nil
}

func (c *GRPCAdminClient) ReloadStore(ctx context.Context, wait bool) error {
	req := &requestv1.ReloadStoreRequest{
		Wait: wait,
	}
	if err := internal.Validate(req); err != nil {
		return fmt.Errorf("could not validate reload store request: %w", err)
	}

	_, err := c.client.ReloadStore(metadata.AppendToOutgoingContext(ctx, c.headers...), req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return fmt.Errorf("could not reload store: %w", err)
	}

	return nil
}
