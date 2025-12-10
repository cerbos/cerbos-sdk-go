// Copyright 2021-2025 Zenauth Ltd.
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

	authorizationv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
	baseURL    string
	httpClient *http.Client
	headers    map[string]string
	userAgent  string
}

// Opt is a functional option for configuring the Client.
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

func WithUDS(socketPath string) Opt {
	return func(c *Client) {
		dialer := &net.Dialer{}
		c.httpClient.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		}
	}
}

func WithInsecureUDS(socketPath string) Opt {
	return func(c *Client) {
		dialer := &net.Dialer{}
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		}
	}
}

// NewClient creates a new AuthZEN HTTP client.
// The baseURL should be the full URL to the Cerbos server (e.g., "https://localhost:3592").
func NewClient(baseURL string, opts ...Opt) (*Client, error) {
	// Validate and normalize base URL
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

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
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
	req := &authorizationv1.AccessEvaluationRequest{
		Subject:  subject.Proto(),
		Resource: resource.Proto(),
		Action:   action.Proto(),
	}

	if evalContext != nil {
		req.Context = evalContext.Data()
	}

	// Make HTTP request
	resp := &authorizationv1.AccessEvaluationResponse{}
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

	req := &authorizationv1.AccessEvaluationBatchRequest{}

	if batchReq.DefaultSubject != nil {
		req.Subject = batchReq.DefaultSubject.Proto()
	}
	if batchReq.DefaultResource != nil {
		req.Resource = batchReq.DefaultResource.Proto()
	}
	if batchReq.DefaultAction != nil {
		req.Action = batchReq.DefaultAction.Proto()
	}
	if batchReq.DefaultContext != nil {
		req.Context = batchReq.DefaultContext.Data()
	}
	if batchReq.Semantics != "" {
		req.Options = &authorizationv1.AccessEvaluationsOptions{
			EvaluationsSemantic: string(batchReq.Semantics),
		}
	}
	// Build evaluations list
	req.Evaluations = make([]*authorizationv1.AccessEvaluationBatchRequest_Evaluation, len(batchReq.Evaluations))
	for i, eval := range batchReq.Evaluations {
		e := &authorizationv1.AccessEvaluationBatchRequest_Evaluation{}

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

	resp := &authorizationv1.AccessEvaluationBatchResponse{}
	if err := c.doRequest(ctx, http.MethodPost, accessEvaluationsPath, req, resp); err != nil {
		return nil, err
	}

	return &AccessEvaluationBatchResult{
		AccessEvaluationBatchResponse: resp,
	}, nil
}

// GetMetadata retrieves the AuthZEN configuration metadata.
func (c *Client) GetMetadata(ctx context.Context) (*authorizationv1.MetadataResponse, error) {
	req := authorizationv1.MetadataRequest{}
	resp := authorizationv1.MetadataResponse{}
	if err := c.doRequest(ctx, http.MethodGet, metadataPath, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, reqBody, respBody proto.Message) error {
	url := c.baseURL + path
	var bodyReader io.Reader
	if reqBody != nil {
		marshaler := protojson.MarshalOptions{
			UseProtoNames:   true,
			EmitUnpopulated: false,
		}
		jsonData, err := marshaler.Marshal(reqBody)
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
