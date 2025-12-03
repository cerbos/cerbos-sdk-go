// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
	defaultUserAgent      = "cerbos-sdk-go-authzen/0.1.0"
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

	// Build protobuf request
	req := &authorizationv1.AccessEvaluationBatchRequest{}

	// Set defaults
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

	// Note: Evaluation semantics (execute_all, deny_on_first_deny, permit_on_first_permit)
	// are not currently supported in the protobuf definition but are part of the AuthZEN spec.
	// This will be added when the protobuf is updated.
	_ = batchReq.Semantics // Avoid unused variable warning

	// Make HTTP request
	resp := &authorizationv1.AccessEvaluationBatchResponse{}
	if err := c.doRequest(ctx, http.MethodPost, accessEvaluationsPath, req, resp); err != nil {
		return nil, err
	}

	return &AccessEvaluationBatchResult{
		AccessEvaluationBatchResponse: resp,
	}, nil
}

// GetMetadata retrieves the AuthZEN configuration metadata.
func (c *Client) GetMetadata(ctx context.Context) (*MetadataResponse, error) {
	var metadata MetadataResponse
	if err := c.doRequest(ctx, http.MethodGet, metadataPath, nil, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// doRequest performs an HTTP request and handles marshaling/unmarshaling.
func (c *Client) doRequest(ctx context.Context, method, path string, reqBody, respBody any) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if reqBody != nil {
		// Marshal request body using protojson for protobuf messages
		var jsonData []byte
		var err error

		switch v := reqBody.(type) {
		case proto.Message:
			// Use protojson for protobuf messages
			marshaler := protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}
			jsonData, err = marshaler.Marshal(v)
		default:
			// Use standard JSON for other types
			jsonData, err = json.Marshal(v)
		}

		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if bodyReader != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}
	req.Header.Set("Accept", contentTypeJSON)
	req.Header.Set("User-Agent", c.userAgent)

	// Add custom headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	// Perform request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Unmarshal response
	if respBody != nil {
		var err error
		switch v := respBody.(type) {
		case proto.Message:
			// Use protojson for protobuf messages
			unmarshaler := protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}
			err = unmarshaler.Unmarshal(body, v)
		default:
			// Use standard JSON for other types
			err = json.Unmarshal(body, v)
		}

		if err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// MetadataResponse represents the AuthZEN configuration metadata.
type MetadataResponse struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`       //nolint:tagliatelle // AuthZEN spec
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`  //nolint:tagliatelle // AuthZEN spec
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"` //nolint:tagliatelle // AuthZEN spec
}
