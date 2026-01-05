// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal"
	internalgrpc "github.com/cerbos/cerbos-sdk-go/internal/grpc"
	svcv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultTimeout        = 30 * time.Second
	accessEvaluationPath  = "/access/v1/evaluation"
	accessEvaluationsPath = "/access/v1/evaluations"
	metadataPath          = "/.well-known/authzen-configuration"
	contentTypeJSON       = "application/json"
	defaultUserAgent      = "cerbos-sdk-go-authzen"
)

// Client provides access to the AuthZEN Authorization API over HTTP.
type Client struct {
	stub       svcv1.AuthorizationServiceClient
	httpClient *http.Client
	headers    map[string]string
	opts       *internal.ReqOpt
	baseURL    string
	userAgent  string
}

// Opt is a functional option for configuring the HTTP Client created by NewClient.
// GRPC client, created by NewGRPCClient, is configured by cerbos.Opt options.
type Opt func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Opt {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) Opt {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithHeaders sets custom headers to be included in all requests.
func WithHeaders(headers map[string]string) Opt {
	return func(c *Client) {
		maps.Copy(c.headers, headers)
	}
}

// WithUserAgent sets a custom user agent string.
func WithUserAgent(userAgent string) Opt {
	return func(c *Client) {
		c.userAgent = userAgent
	}
}

func WithTLSConfig(tlsConf *tls.Config) Opt {
	return func(c *Client) {
		if t, _ := c.httpClient.Transport.(*http.Transport); t == nil {
			c.httpClient.Transport = &http.Transport{
				TLSClientConfig: tlsConf,
			}
		} else {
			t.TLSClientConfig = tlsConf
		}
	}
}

// WithTLSInsecure enables skipping TLS certificate verification.
func WithTLSInsecure() Opt {
	return func(c *Client) {
		tlsConf := tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}
		if t, _ := c.httpClient.Transport.(*http.Transport); t == nil {
			c.httpClient.Transport = &http.Transport{
				TLSClientConfig: &tlsConf,
			}
		} else {
			t.TLSClientConfig = &tlsConf
		}
	}
}

// WithUDS configures the client to connect over Unix Domain Socket.
func WithUDS(socketPath string) Opt {
	return func(c *Client) {
		dialer := &net.Dialer{}
		dialContext := func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		if t, _ := c.httpClient.Transport.(*http.Transport); t == nil {
			c.httpClient.Transport = &http.Transport{
				DialContext: dialContext,
			}
		} else {
			t.DialContext = dialContext
		}
	}
}

func mergeWithReqOpts(ctx context.Context, evalContext *Context, opts *internal.ReqOpt) map[string]*structpb.Value {
	evalContext.Data()
	if opts == nil {
		return evalContext.Data()
	}
	if evalContext == nil {
		evalContext = NewContext().
			WithIncludeMeta(opts.IncludeMeta)
	}
	if opts.AuxData != nil {
		evalContext = evalContext.WithAuxData(opts.AuxData)
	}
	if opts.RequestIDGenerator != nil {
		evalContext = evalContext.WithRequestID(opts.RequestIDGenerator(ctx))
	}
	return evalContext.Data()
}

func NewClient(address string, opts ...cerbos.Opt) (*Client, error) {
	conf := internalgrpc.NewConfig(address)

	for _, o := range opts {
		o(conf)
	}

	grpcConn, err := internalgrpc.MkConn(conf)
	if err != nil {
		return nil, err
	}

	return &Client{stub: svcv1.NewAuthorizationServiceClient(grpcConn)}, nil
}

// NewHTTPClient creates a new AuthZEN HTTP client.
// The baseURL should be the full URL to the Cerbos server (e.g., "https://pdp.example.com:3592").
func NewHTTPClient(baseURL string, opts ...Opt) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL cannot be empty")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}

	// Remove trailing slash from base URL
	baseURL = strings.TrimSuffix(u.String(), "/")

	client := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		headers:   make(map[string]string),
		userAgent: defaultUserAgent,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// IsAllowed checks if a subject is allowed to perform an action on a resource.
func (c *Client) IsAllowed(ctx context.Context, subj *Subject, resource *Resource, action string, evalContext *Context) (bool, error) {
	eval, err := c.AccessEvaluation(ctx, subj, resource, NewAction(action), evalContext)
	if err != nil {
		return false, err
	}
	return *eval.Decision, nil
}

// AccessEvaluation evaluates whether a subject can perform a single action on a single resource.
// Returns the decision and optionally the full response context.
func (c *Client) AccessEvaluation(ctx context.Context, subject *Subject, resource *Resource, action *Action, evalContext *Context) (*AccessEvaluationResult, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject cannot be nil")
	}
	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}
	if action == nil {
		return nil, fmt.Errorf("action cannot be nil")
	}

	// Build request
	req := &svcv1.AccessEvaluationRequest{
		Subject:  subject.Proto(),
		Resource: resource.Proto(),
		Action:   action.Proto(),
		Context:  mergeWithReqOpts(ctx, evalContext, c.opts),
	}

	if c.stub != nil {
		resp, err := c.stub.AccessEvaluation(ctx, req)
		if err != nil {
			return nil, err
		}
		return &AccessEvaluationResult{
			AccessEvaluationResponse: resp,
		}, nil
	}
	// Make HTTP request
	resp := &svcv1.AccessEvaluationResponse{}
	if err := c.doRequest(ctx, http.MethodPost, accessEvaluationPath, req, resp); err != nil {
		return nil, err
	}

	return &AccessEvaluationResult{
		AccessEvaluationResponse: resp,
	}, nil
}

// EvaluationSemantics defines how batch evaluations should be processed.
type EvaluationSemantics string

const (
	// ExecuteAll processes all evaluations regardless of individual results (default).
	ExecuteAll EvaluationSemantics = "execute_all"
	// DenyOnFirstDeny stops processing after the first denial.
	DenyOnFirstDeny EvaluationSemantics = "deny_on_first_deny"
	// PermitOnFirstPermit stops processing after the first permit.
	PermitOnFirstPermit EvaluationSemantics = "permit_on_first_permit"
)

// BatchEvaluation represents a single evaluation in a batch request.
type BatchEvaluation struct {
	Subject  *Subject
	Resource *Resource
	Action   *Action
	Context  *Context
}

// BatchEvaluationRequest represents a batch evaluation request with defaults and per-evaluation overrides.
type BatchEvaluationRequest struct {
	DefaultSubject  *Subject
	DefaultResource *Resource
	DefaultAction   *Action
	DefaultContext  *Context
	Semantics       EvaluationSemantics
	Evaluations     []BatchEvaluation
}

// AccessEvaluations evaluates multiple access requests in a single call.
// Supports default values that can be overridden for individual evaluations.
func (c *Client) AccessEvaluations(ctx context.Context, batchReq *BatchEvaluationRequest) (*AccessEvaluationBatchResult, error) {
	if batchReq == nil {
		return nil, fmt.Errorf("batch request cannot be nil")
	}

	if len(batchReq.Evaluations) == 0 {
		return nil, fmt.Errorf("batch request must contain at least one evaluation")
	}

	req := &svcv1.AccessEvaluationBatchRequest{}

	if batchReq.DefaultSubject != nil {
		req.Subject = batchReq.DefaultSubject.Proto()
	}
	if batchReq.DefaultResource != nil {
		req.Resource = batchReq.DefaultResource.Proto()
	}
	if batchReq.DefaultAction != nil {
		req.Action = batchReq.DefaultAction.Proto()
	}
	req.Context = mergeWithReqOpts(ctx, batchReq.DefaultContext, c.opts)

	if batchReq.Semantics != "" {
		req.Options = &svcv1.AccessEvaluationsOptions{
			EvaluationsSemantic: string(batchReq.Semantics),
		}
	}
	// Build evaluations list
	req.Evaluations = make([]*svcv1.AccessEvaluationBatchRequest_Evaluation, len(batchReq.Evaluations))
	for i, eval := range batchReq.Evaluations {
		e := &svcv1.AccessEvaluationBatchRequest_Evaluation{}

		if eval.Subject != nil {
			e.Subject = eval.Subject.Proto()
		}
		if eval.Resource != nil {
			e.Resource = eval.Resource.Proto()
		}
		if eval.Action != nil {
			e.Action = eval.Action.Proto()
		}
		if eval.Context != nil {
			e.Context = eval.Context.Data()
		}

		req.Evaluations[i] = e
	}
	if c.stub != nil {
		resp, err := c.stub.AccessEvaluationBatch(ctx, req)
		if err != nil {
			return nil, err
		}
		return &AccessEvaluationBatchResult{
			AccessEvaluationBatchResponse: resp,
		}, nil
	}
	resp := &svcv1.AccessEvaluationBatchResponse{}
	if err := c.doRequest(ctx, http.MethodPost, accessEvaluationsPath, req, resp); err != nil {
		return nil, err
	}

	return &AccessEvaluationBatchResult{
		AccessEvaluationBatchResponse: resp,
	}, nil
}

func (c *Client) With(reqOpts ...cerbos.RequestOpt) *Client {
	opts := &internal.ReqOpt{}
	for _, ro := range reqOpts {
		ro(opts)
	}
	c.opts = opts
	return c
}

// GetMetadata retrieves the AuthZEN configuration metadata.
func (c *Client) GetMetadata(ctx context.Context) (*svcv1.MetadataResponse, error) {
	req := &svcv1.MetadataRequest{}
	if c.stub != nil {
		resp, err := c.stub.Metadata(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	resp := &svcv1.MetadataResponse{}
	if err := c.doRequest(ctx, http.MethodGet, metadataPath, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, reqBody, respBody proto.Message) error {
	url := c.baseURL + path
	var bodyReader io.Reader
	if reqBody != nil {
		jsonData, err := protojson.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if bodyReader != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}
	req.Header.Set("Accept", contentTypeJSON)
	req.Header.Set("User-Agent", c.userAgent)

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	if respBody != nil {
		unmarshaler := protojson.UnmarshalOptions{
			DiscardUnknown: true,
		}
		if err := unmarshaler.Unmarshal(body, respBody); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

type SubjectCtx struct {
	client *Client
	subj   *Subject
	ctx    *Context
}

// WithSubject creates a subject-scoped context.
func (c *Client) WithSubject(subj *Subject) *SubjectCtx {
	return &SubjectCtx{client: c, subj: subj}
}

// Subject returns the subject attached to this context.
func (sc *SubjectCtx) Subject() *Subject {
	return sc.subj
}

// WithEvalContext add AuthZEN evaluation context to the subject-scoped context.
func (sc *SubjectCtx) WithEvalContext(ctx *Context) {
	sc.ctx = ctx
}

// IsAllowed checks if the subject is allowed to perform an action on a resource.
func (sc *SubjectCtx) IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error) {
	return sc.client.IsAllowed(ctx, sc.subj, resource, action, sc.ctx)
}
