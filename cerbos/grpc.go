// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/stats"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

var _ Client[*GRPCClient, PrincipalCtx] = (*GRPCClient)(nil)

type Opt func(*internal.Config)

// WithPlaintext configures the client to connect over h2c.
func WithPlaintext() Opt {
	return func(c *internal.Config) {
		c.Plaintext = true
	}
}

// WithTLSAuthority overrides the remote server authority if it is different from what is provided in the address.
func WithTLSAuthority(authority string) Opt {
	return func(c *internal.Config) {
		c.TLSAuthority = authority
	}
}

// WithTLSInsecure enables skipping TLS certificate verification.
func WithTLSInsecure() Opt {
	return func(c *internal.Config) {
		c.TLSInsecure = true
	}
}

// WithTLSCACert sets the CA certificate chain to use for certificate verification.
func WithTLSCACert(certPath string) Opt {
	return func(c *internal.Config) {
		c.TLSCACert = certPath
	}
}

// WithTLSClientCert sets the client certificate to use to authenticate to the server.
func WithTLSClientCert(cert, key string) Opt {
	return func(c *internal.Config) {
		c.TLSClientCert = cert
		c.TLSClientKey = key
	}
}

// WithConnectTimeout sets the connection establishment timeout.
func WithConnectTimeout(timeout time.Duration) Opt {
	return func(c *internal.Config) {
		c.ConnectTimeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retries per call.
func WithMaxRetries(retries uint) Opt {
	return func(c *internal.Config) {
		c.MaxRetries = retries
	}
}

// WithRetryTimeout sets the timeout per retry attempt.
func WithRetryTimeout(timeout time.Duration) Opt {
	return func(c *internal.Config) {
		c.RetryTimeout = timeout
	}
}

// WithUserAgent sets the user agent string.
func WithUserAgent(ua string) Opt {
	return func(c *internal.Config) {
		c.UserAgent = ua
	}
}

// WithPlaygroundInstance sets the Cerbos playground instance to use as the source of policies.
// Note that Playground instances are for demonstration purposes only and do not provide any
// performance or availability guarantees.
func WithPlaygroundInstance(instance string) Opt {
	return func(c *internal.Config) {
		c.PlaygroundInstance = instance
	}
}

// WithStreamInterceptors sets the interceptors to be used for streaming gRPC operations.
func WithStreamInterceptors(interceptors ...grpc.StreamClientInterceptor) Opt {
	return func(c *internal.Config) {
		c.StreamInterceptors = interceptors
	}
}

// WithUnaryInterceptors sets the interceptors to be used for unary gRPC operations.
func WithUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) Opt {
	return func(c *internal.Config) {
		c.UnaryInterceptors = interceptors
	}
}

// WithStatsHandler sets the gRPC stats handler for the connection.
func WithStatsHandler(handler stats.Handler) Opt {
	return func(c *internal.Config) {
		c.StatsHandler = handler
	}
}

// WithMaxRecvMsgSizeBytes sets the maximum size of a single response payload that can be received from the server.
func WithMaxRecvMsgSizeBytes(size uint) Opt {
	return func(c *internal.Config) {
		c.MaxRecvMsgSizeBytes = size
	}
}

// WithMaxSendMsgSizeBytes sets the maximum size of a single request payload that can be sent to the server.
func WithMaxSendMsgSizeBytes(size uint) Opt {
	return func(c *internal.Config) {
		c.MaxSendMsgSizeBytes = size
	}
}

// New creates a new Cerbos client.
func New(address string, opts ...Opt) (*GRPCClient, error) {
	grpcConn, _, err := mkConn(address, opts...)
	if err != nil {
		return nil, err
	}

	return &GRPCClient{stub: svcv1.NewCerbosServiceClient(grpcConn)}, nil
}

func mkConn(address string, opts ...Opt) (*grpc.ClientConn, *internal.Config, error) {
	conf := &internal.Config{
		Address:        address,
		ConnectTimeout: 30 * time.Second, //nolint:mnd
		MaxRetries:     3,                //nolint:mnd
		RetryTimeout:   2 * time.Second,  //nolint:mnd
		UserAgent:      internal.UserAgent("grpc"),
	}

	for _, o := range opts {
		o(conf)
	}

	dialOpts, err := mkDialOpts(conf)
	if err != nil {
		return nil, nil, err
	}

	grpcConn, err := grpc.NewClient(conf.Address, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, conf, nil
}

func mkDialOpts(conf *internal.Config) ([]grpc.DialOption, error) {
	dialOpts := []grpc.DialOption{grpc.WithUserAgent(conf.UserAgent)}

	if conf.StatsHandler != nil {
		dialOpts = append(dialOpts, grpc.WithStatsHandler(conf.StatsHandler))
	}

	if conf.ConnectTimeout > 0 {
		dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: conf.ConnectTimeout}))
	}

	streamInterceptors := conf.StreamInterceptors
	unaryInterceptors := conf.UnaryInterceptors

	if conf.MaxRetries > 0 && conf.RetryTimeout > 0 {
		streamInterceptors = append(
			[]grpc.StreamClientInterceptor{
				grpc_retry.StreamClientInterceptor(
					grpc_retry.WithMax(conf.MaxRetries),
					grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
				),
			},
			streamInterceptors...,
		)

		unaryInterceptors = append(
			[]grpc.UnaryClientInterceptor{
				grpc_retry.UnaryClientInterceptor(
					grpc_retry.WithMax(conf.MaxRetries),
					grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
				),
			},
			unaryInterceptors...,
		)
	}

	if len(streamInterceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainStreamInterceptor(streamInterceptors...))
	}

	if len(unaryInterceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainUnaryInterceptor(unaryInterceptors...))
	}

	if conf.Plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConf, err := mkTLSConfig(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		if conf.TLSAuthority != "" {
			dialOpts = append(dialOpts, grpc.WithAuthority(conf.TLSAuthority))
		}
	}

	if conf.PlaygroundInstance != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(newPlaygroundInstanceCredentials(conf.PlaygroundInstance)))
	}

	defaultCallOptions := []grpc.CallOption{grpc.UseCompressor(gzip.Name)}
	if conf.MaxRecvMsgSizeBytes > 0 {
		defaultCallOptions = append(defaultCallOptions, grpc.MaxCallRecvMsgSize(int(conf.MaxRecvMsgSizeBytes))) //nolint:gosec
	}

	if conf.MaxSendMsgSizeBytes > 0 {
		defaultCallOptions = append(defaultCallOptions, grpc.MaxCallSendMsgSize(int(conf.MaxSendMsgSizeBytes))) //nolint:gosec
	}

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(defaultCallOptions...))

	return dialOpts, nil
}

func mkTLSConfig(conf *internal.Config) (*tls.Config, error) {
	tlsConf := internal.DefaultTLSConfig()

	if conf.TLSInsecure {
		tlsConf.InsecureSkipVerify = true
	}

	if conf.TLSCACert != "" {
		bs, err := os.ReadFile(conf.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %s: %w", conf.TLSCACert, err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append CA certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if conf.TLSClientCert != "" && conf.TLSClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(conf.TLSClientCert, conf.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from [%s, %s]: %w", conf.TLSClientCert, conf.TLSClientKey, err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}

type GRPCClient struct {
	stub svcv1.CerbosServiceClient
	opts *internal.ReqOpt
}

func (c *GRPCClient) PlanResources(ctx context.Context, principal *Principal, resource *Resource, actions ...string) (*PlanResourcesResponse, error) {
	if err := internal.IsValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	// ResourceQueryPlan.Resource object doesn't have an ID field, since it doesn't describe a concrete instance,
	// but a set of resources. To workaround resource validation we assign a dummyID to resource.r.Id field,
	// in case it is empty.
	if resource != nil && resource.Obj != nil && resource.Obj.Id == "" {
		resource.Obj.Id = "dummyID"
	}

	if err := internal.IsValid(resource); err != nil {
		return nil, fmt.Errorf("invalid resource: %w", err)
	}

	req := &requestv1.PlanResourcesRequest{
		RequestId: c.opts.RequestID(ctx),
		Actions:   actions,
		Principal: principal.Obj,
		Resource: &enginev1.PlanResourcesInput_Resource{
			Kind:          resource.Obj.Kind,
			Attr:          resource.Obj.Attr,
			PolicyVersion: resource.Obj.PolicyVersion,
			Scope:         resource.Obj.Scope,
		},
	}

	if c.opts != nil {
		req.AuxData = c.opts.AuxData
		req.IncludeMeta = c.opts.IncludeMeta
	}

	result, err := c.stub.PlanResources(c.opts.Context(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &PlanResourcesResponse{PlanResourcesResponse: result}, nil
}

func (c *GRPCClient) CheckResources(ctx context.Context, principal *Principal, resourceBatch *ResourceBatch) (*CheckResourcesResponse, error) {
	if err := internal.IsValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	if err := internal.IsValid(resourceBatch); err != nil {
		return nil, fmt.Errorf("invalid resource batch; %w", err)
	}

	req := &requestv1.CheckResourcesRequest{
		RequestId: c.opts.RequestID(ctx),
		Principal: principal.Obj,
		Resources: resourceBatch.Batch,
	}

	if c.opts != nil {
		req.AuxData = c.opts.AuxData
		req.IncludeMeta = c.opts.IncludeMeta
	}

	result, err := c.stub.CheckResources(c.opts.Context(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourcesResponse{CheckResourcesResponse: result}, nil
}

func (c *GRPCClient) IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error) {
	if err := internal.IsValid(principal); err != nil {
		return false, fmt.Errorf("invalid principal: %w", err)
	}

	if err := internal.IsValid(resource); err != nil {
		return false, fmt.Errorf("invalid resource: %w", err)
	}

	req := &requestv1.CheckResourcesRequest{
		RequestId: c.opts.RequestID(ctx),
		Principal: principal.Obj,
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{
			{Actions: []string{action}, Resource: resource.Obj},
		},
	}

	if c.opts != nil {
		req.AuxData = c.opts.AuxData
		req.IncludeMeta = c.opts.IncludeMeta
	}

	result, err := c.stub.CheckResources(c.opts.Context(ctx), req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	if len(result.Results) == 0 {
		return false, fmt.Errorf("unexpected response from server")
	}

	return result.Results[0].Actions[action] == effectv1.Effect_EFFECT_ALLOW, nil
}

func (c *GRPCClient) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	resp, err := c.stub.ServerInfo(c.opts.Context(ctx), &requestv1.ServerInfoRequest{})
	if err != nil {
		return nil, err
	}
	return &ServerInfo{
		ServerInfoResponse: resp,
	}, nil
}

func (c *GRPCClient) With(reqOpts ...RequestOpt) *GRPCClient {
	opts := &internal.ReqOpt{}
	for _, ro := range reqOpts {
		ro(opts)
	}

	return &GRPCClient{opts: opts, stub: c.stub}
}

func (c *GRPCClient) WithPrincipal(p *Principal) PrincipalCtx {
	return PrincipalCtx{client: c, principal: p}
}

type PrincipalCtx struct {
	client    *GRPCClient
	principal *Principal
}

func (pc PrincipalCtx) Principal() *Principal {
	return pc.principal
}

func (pc PrincipalCtx) IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error) {
	return pc.client.IsAllowed(ctx, pc.principal, resource, action)
}

func (pc PrincipalCtx) CheckResources(ctx context.Context, batch *ResourceBatch) (*CheckResourcesResponse, error) {
	return pc.client.CheckResources(ctx, pc.principal, batch)
}

func (pc PrincipalCtx) PlanResources(ctx context.Context, resource *Resource, actions ...string) (*PlanResourcesResponse, error) {
	return pc.client.PlanResources(ctx, pc.principal, resource, actions...)
}
