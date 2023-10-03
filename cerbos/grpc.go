// Copyright 2021-2023 Zenauth Ltd.
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

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/rs/xid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

var _ Client[*GRPCClient, PrincipalCtx] = (*GRPCClient)(nil)

type config struct {
	address            string
	tlsAuthority       string
	tlsCACert          string
	tlsClientCert      string
	tlsClientKey       string
	userAgent          string
	playgroundInstance string
	streamInterceptors []grpc.StreamClientInterceptor
	unaryInterceptors  []grpc.UnaryClientInterceptor
	connectTimeout     time.Duration
	retryTimeout       time.Duration
	maxRetries         uint
	plaintext          bool
	tlsInsecure        bool
}

type Opt func(*config)

// WithPlaintext configures the client to connect over h2c.
func WithPlaintext() Opt {
	return func(c *config) {
		c.plaintext = true
	}
}

// WithTLSAuthority overrides the remote server authority if it is different from what is provided in the address.
func WithTLSAuthority(authority string) Opt {
	return func(c *config) {
		c.tlsAuthority = authority
	}
}

// WithTLSInsecure enables skipping TLS certificate verification.
func WithTLSInsecure() Opt {
	return func(c *config) {
		c.tlsInsecure = true
	}
}

// WithTLSCACert sets the CA certificate chain to use for certificate verification.
func WithTLSCACert(certPath string) Opt {
	return func(c *config) {
		c.tlsCACert = certPath
	}
}

// WithTLSClientCert sets the client certificate to use to authenticate to the server.
func WithTLSClientCert(cert, key string) Opt {
	return func(c *config) {
		c.tlsClientCert = cert
		c.tlsClientKey = key
	}
}

// WithConnectTimeout sets the connection establishment timeout.
func WithConnectTimeout(timeout time.Duration) Opt {
	return func(c *config) {
		c.connectTimeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retries per call.
func WithMaxRetries(retries uint) Opt {
	return func(c *config) {
		c.maxRetries = retries
	}
}

// WithRetryTimeout sets the timeout per retry attempt.
func WithRetryTimeout(timeout time.Duration) Opt {
	return func(c *config) {
		c.retryTimeout = timeout
	}
}

// WithUserAgent sets the user agent string.
func WithUserAgent(ua string) Opt {
	return func(c *config) {
		c.userAgent = ua
	}
}

// WithPlaygroundInstance sets the Cerbos playground instance to use as the source of policies.
// Note that Playground instances are for demonstration purposes only and do not provide any
// performance or availability guarantees.
func WithPlaygroundInstance(instance string) Opt {
	return func(c *config) {
		c.playgroundInstance = instance
	}
}

// WithStreamInterceptors sets the interceptors to be used for streaming gRPC operations.
func WithStreamInterceptors(interceptors ...grpc.StreamClientInterceptor) Opt {
	return func(c *config) {
		c.streamInterceptors = interceptors
	}
}

// WithUnaryInterceptors sets the interceptors to be used for unary gRPC operations.
func WithUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) Opt {
	return func(c *config) {
		c.unaryInterceptors = interceptors
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

func mkConn(address string, opts ...Opt) (*grpc.ClientConn, *config, error) {
	conf := &config{
		address:        address,
		connectTimeout: 30 * time.Second, //nolint:gomnd
		maxRetries:     3,                //nolint:gomnd
		retryTimeout:   2 * time.Second,  //nolint:gomnd
		userAgent:      internal.UserAgent("grpc"),
	}

	for _, o := range opts {
		o(conf)
	}

	dialOpts, err := mkDialOpts(conf)
	if err != nil {
		return nil, nil, err
	}

	grpcConn, err := grpc.Dial(conf.address, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, conf, nil
}

func mkDialOpts(conf *config) ([]grpc.DialOption, error) {
	dialOpts := []grpc.DialOption{grpc.WithUserAgent(conf.userAgent)}

	if conf.connectTimeout > 0 {
		dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: conf.connectTimeout}))
	}

	streamInterceptors := conf.streamInterceptors
	unaryInterceptors := conf.unaryInterceptors

	if conf.maxRetries > 0 && conf.retryTimeout > 0 {
		streamInterceptors = append(
			[]grpc.StreamClientInterceptor{
				grpc_retry.StreamClientInterceptor(
					grpc_retry.WithMax(conf.maxRetries),
					grpc_retry.WithPerRetryTimeout(conf.retryTimeout),
				),
			},
			streamInterceptors...,
		)

		unaryInterceptors = append(
			[]grpc.UnaryClientInterceptor{
				grpc_retry.UnaryClientInterceptor(
					grpc_retry.WithMax(conf.maxRetries),
					grpc_retry.WithPerRetryTimeout(conf.retryTimeout),
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

	if conf.plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConf, err := mkTLSConfig(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		if conf.tlsAuthority != "" {
			dialOpts = append(dialOpts, grpc.WithAuthority(conf.tlsAuthority))
		}
	}

	if conf.playgroundInstance != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(newPlaygroundInstanceCredentials(conf.playgroundInstance)))
	}

	return dialOpts, nil
}

func mkTLSConfig(conf *config) (*tls.Config, error) {
	tlsConf := internal.DefaultTLSConfig()

	if conf.tlsInsecure {
		tlsConf.InsecureSkipVerify = true
	}

	if conf.tlsCACert != "" {
		bs, err := os.ReadFile(conf.tlsCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %s: %w", conf.tlsCACert, err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append CA certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if conf.tlsClientCert != "" && conf.tlsClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(conf.tlsClientCert, conf.tlsClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from [%s, %s]: %w", conf.tlsClientCert, conf.tlsClientKey, err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}

type GRPCClient struct {
	stub svcv1.CerbosServiceClient
	opts *internal.ReqOpt
}

func (c *GRPCClient) PlanResources(ctx context.Context, principal *Principal, resource *Resource, action string) (*PlanResourcesResponse, error) {
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

	reqID := xid.New()
	req := &requestv1.PlanResourcesRequest{
		RequestId: reqID.String(),
		Action:    action,
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

	result, err := c.stub.PlanResources(ctx, req)
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

	reqID := xid.New()
	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.Obj,
		Resources: resourceBatch.Batch,
	}

	if c.opts != nil {
		req.AuxData = c.opts.AuxData
		req.IncludeMeta = c.opts.IncludeMeta
	}

	result, err := c.stub.CheckResources(ctx, req)
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

	reqID := xid.New()
	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.Obj,
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{
			{Actions: []string{action}, Resource: resource.Obj},
		},
	}

	if c.opts != nil {
		req.AuxData = c.opts.AuxData
		req.IncludeMeta = c.opts.IncludeMeta
	}

	result, err := c.stub.CheckResources(ctx, req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	if len(result.Results) == 0 {
		return false, fmt.Errorf("unexpected response from server")
	}

	return result.Results[0].Actions[action] == effectv1.Effect_EFFECT_ALLOW, nil
}

func (c *GRPCClient) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	resp, err := c.stub.ServerInfo(ctx, &requestv1.ServerInfoRequest{})
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

func (pc PrincipalCtx) PlanResources(ctx context.Context, resource *Resource, action string) (*PlanResourcesResponse, error) {
	return pc.client.PlanResources(ctx, pc.principal, resource, action)
}
