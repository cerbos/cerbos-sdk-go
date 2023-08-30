// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package client provides a client implementation to interact with a Cerbos instance and check access policies.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/xid"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"

	effectv1 "github.com/cerbos/cerbos-sdk-go/client/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos-sdk-go/client/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos-sdk-go/client/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos-sdk-go/client/genpb/cerbos/svc/v1/svcv1connect"
)

var (
	errPlaygroundRequiresTLS = errors.New("playground cannot be accessed over a plaintext connection: remove the WithPlaintext() option")
)

/*
// Client provides access to the Cerbos API.
type Client interface {
	// IsAllowed checks access to a single resource by a principal and returns true if access is granted.
	IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error)
	// CheckResources checks access to a batch of resources of different kinds.
	CheckResources(ctx context.Context, principal *Principal, resources *ResourceBatch) (*CheckResourcesResponse, error)
	// ServerInfo retrieves server information.
	ServerInfo(ctx context.Context) (*ServerInfo, error)
	// With sets per-request options for the client.
	With(opts ...RequestOpt) Client
	// PlanResources creates a query plan for performing the given action on a set of resources of the given kind.
	PlanResources(ctx context.Context, principal *Principal, resource *Resource, action string) (*PlanResourcesResponse, error)
	// WithPrincipal sets the principal to be used for subsequent API calls.
	// WithPrincipal sets the principal to be used for subsequent API calls.
	WithPrincipal(principal *Principal) PrincipalContext
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
*/

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
	requestTimeout     time.Duration
	retryWaitMin       time.Duration
	retryWaitMax       time.Duration
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

// WithRetryWait sets the minimum and maximum wait duration before retrying a request.
// The actual wait time will be a value that falls between this range.
func WithRetryWait(minWait, maxWait time.Duration) Opt {
	return func(c *config) {
		c.retryWaitMin = minWait
		c.retryWaitMax = maxWait
	}
}

// WithRequestTimeout sets the timeout per request.
func WithRequestTimeout(timeout time.Duration) Opt {
	return func(c *config) {
		c.requestTimeout = timeout
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
func New(address string, opts ...Opt) (*Client, error) {
	conf := config{
		address:        address,
		connectTimeout: 30 * time.Second,       //nolint:gomnd
		maxRetries:     3,                      //nolint:gomnd
		retryWaitMin:   100 * time.Millisecond, //nolint:gomnd
		retryWaitMax:   500 * time.Millisecond, //nolint:gomnd
		requestTimeout: 1 * time.Second,        //nolint:gomnd
		userAgent:      mkUserAgent(),
	}

	for _, o := range opts {
		o(&conf)
	}

	httpClient, err := mkRetryableHTTPClient(conf)
	if err != nil {
		return nil, err
	}

	options := []connect.ClientOption{
		connect.WithGRPC(),
		connect.WithCompressMinBytes(1024),
		connect.WithInterceptors(
			otelconnect.NewInterceptor(),
			newUserAgentInterceptor(conf.userAgent),
		),
	}

	if conf.playgroundInstance != "" {
		if conf.plaintext {
			return nil, errPlaygroundRequiresTLS
		}
		options = append(options, connect.WithInterceptors(newPlaygroundInterceptor(conf.playgroundInstance)))
	}

	client := svcv1connect.NewCerbosServiceClient(httpClient, conf.address, options...)
	return &Client{client: client}, nil
}

func mkUserAgent() string {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/cerbos/cerbos-sdk-go" {
				version = dep.Version
				break
			}
		}
	}

	return fmt.Sprintf("cerbos-sdk-go/%s (%s; %s)", version, runtime.GOOS, runtime.GOARCH)
}

func mkRetryableHTTPClient(conf config) (*http.Client, error) {
	stdClient := &http.Client{
		Timeout: conf.requestTimeout,
	}

	if conf.plaintext {
		stdClient.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	} else {
		tlsConf, err := mkTLSConfig(conf)
		if err != nil {
			return nil, err
		}

		stdClient.Transport = &http2.Transport{
			TLSClientConfig: tlsConf,
		}
	}

	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient = stdClient
	httpClient.RetryMax = int(conf.maxRetries)
	httpClient.RetryWaitMin = conf.retryWaitMin
	httpClient.RetryWaitMax = conf.retryWaitMax

	return httpClient.StandardClient(), nil
}

func mkTLSConfig(conf config) (*tls.Config, error) {
	// See https://wiki.mozilla.org/Security/Server_Side_TLS
	tlsConf := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2"},
	}

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

	if conf.tlsAuthority != "" {
		tlsConf.ServerName = conf.tlsAuthority
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

type Client struct {
	client svcv1connect.CerbosServiceClient
	opts   *reqOpt
}

// PlanResources creates a query plan for performing the given action on a set of resources of the given kind.
// See https://docs.cerbos.dev/cerbos/latest/api/#resources-query-plan
func (c *Client) PlanResources(ctx context.Context, principal *Principal, resource *Resource, action string) (*PlanResourcesResponse, error) {
	if err := isValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	// ResourceQueryPlan.Resource object doesn't have an ID field, since it doesn't describe a concrete instance,
	// but a set of resources. To workaround resource validation we assign a dummyID to resource.r.Id field,
	// in case it is empty.
	if resource != nil && resource.r != nil && resource.r.Id == "" {
		resource.r.Id = "dummyID"
	}

	if err := isValid(resource); err != nil {
		return nil, fmt.Errorf("invalid resource: %w", err)
	}

	reqID := xid.New()
	req := &requestv1.PlanResourcesRequest{
		RequestId: reqID.String(),
		Action:    action,
		Principal: principal.p,
		Resource: &enginev1.PlanResourcesInput_Resource{
			Kind:          resource.r.Kind,
			Attr:          resource.r.Attr,
			PolicyVersion: resource.r.PolicyVersion,
			Scope:         resource.r.Scope,
		},
	}

	if c.opts != nil {
		req.AuxData = c.opts.auxData
		req.IncludeMeta = c.opts.includeMeta
	}

	result, err := c.client.PlanResources(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &PlanResourcesResponse{PlanResourcesResponse: result.Msg}, nil
}

// CheckResources checks access to a batch of resources of different kinds.
// See https://docs.cerbos.dev/cerbos/latest/api/#check-resources
func (c *Client) CheckResources(ctx context.Context, principal *Principal, resourceBatch *ResourceBatch) (*CheckResourcesResponse, error) {
	if err := isValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	if err := isValid(resourceBatch); err != nil {
		return nil, fmt.Errorf("invalid resource batch; %w", err)
	}

	reqID := xid.New()
	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.p,
		Resources: resourceBatch.batch,
	}

	if c.opts != nil {
		req.AuxData = c.opts.auxData
		req.IncludeMeta = c.opts.includeMeta
	}

	result, err := c.client.CheckResources(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourcesResponse{CheckResourcesResponse: result.Msg}, nil
}

// IsAllowed is a convenience method for checking access to a single resource. It returns true if the action is allowed.
func (c *Client) IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error) {
	if err := isValid(principal); err != nil {
		return false, fmt.Errorf("invalid principal: %w", err)
	}

	if err := isValid(resource); err != nil {
		return false, fmt.Errorf("invalid resource: %w", err)
	}

	reqID := xid.New()
	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.p,
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{
			{Actions: []string{action}, Resource: resource.r},
		},
	}

	if c.opts != nil {
		req.AuxData = c.opts.auxData
		req.IncludeMeta = c.opts.includeMeta
	}

	resp, err := c.client.CheckResources(ctx, connect.NewRequest(req))
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	result := resp.Msg

	if len(result.Results) == 0 {
		return false, errors.New("unexpected response from server")
	}

	return result.Results[0].Actions[action] == effectv1.Effect_EFFECT_ALLOW, nil
}

// ServerInfo retrieves Cerbos server information.
// See https://docs.cerbos.dev/cerbos/latest/api/#server-info
func (c *Client) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	resp, err := c.client.ServerInfo(ctx, connect.NewRequest(&requestv1.ServerInfoRequest{}))
	if err != nil {
		return nil, err
	}

	return &ServerInfo{ServerInfoResponse: resp.Msg}, nil
}

// With sets per-request options for the client.
func (c *Client) With(reqOpts ...RequestOpt) *Client {
	opts := &reqOpt{}
	for _, ro := range reqOpts {
		ro(opts)
	}

	return &Client{opts: opts, client: c.client}
}

// WithPrincipal sets the principal to be used for subsequent API calls.
func (c *Client) WithPrincipal(p *Principal) PrincipalCtx {
	return PrincipalCtx{client: c, principal: p}
}

type PrincipalCtx struct {
	client    *Client
	principal *Principal
}

// Principal returns the principal attached to this context.
func (pc PrincipalCtx) Principal() *Principal {
	return pc.principal
}

// IsAllowed is a convenience method for checking access to a single resource. It returns true if the action is allowed.
func (pc PrincipalCtx) IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error) {
	return pc.client.IsAllowed(ctx, pc.principal, resource, action)
}

// CheckResources checks access to a batch of resources of different kinds.
// See https://docs.cerbos.dev/cerbos/latest/api/#check-resources
func (pc PrincipalCtx) CheckResources(ctx context.Context, batch *ResourceBatch) (*CheckResourcesResponse, error) {
	return pc.client.CheckResources(ctx, pc.principal, batch)
}

// PlanResources creates a query plan for performing the given action on a set of resources of the given kind.
// See https://docs.cerbos.dev/cerbos/latest/api/#resources-query-plan
func (pc PrincipalCtx) PlanResources(ctx context.Context, resource *Resource, action string) (*PlanResourcesResponse, error) {
	return pc.client.PlanResources(ctx, pc.principal, resource, action)
}

type validatable interface {
	Err() error
	Validate() error
}

func isValid[T validatable](obj T) error {
	if err := obj.Err(); err != nil {
		return err
	}

	return obj.Validate()
}
