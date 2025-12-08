// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"encoding/json"
	"fmt"

	authorizationv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// AccessEvaluationResult wraps an AuthZEN access evaluation response.
type AccessEvaluationResult struct {
	*authorizationv1.AccessEvaluationResponse
}

// IsAllowed returns true if the access decision is to allow the action.
func (r *AccessEvaluationResult) IsAllowed() bool {
	if r == nil || r.AccessEvaluationResponse == nil {
		return false
	}
	return r.GetDecision()
}

// GetContextValue retrieves a specific value from the response context.
func (r *AccessEvaluationResult) GetContextValue(key string) (*structpb.Value, bool) {
	if r == nil || r.AccessEvaluationResponse == nil {
		return nil, false
	}

	context := r.GetContext()
	if context == nil {
		return nil, false
	}

	val, ok := context[key]
	return val, ok
}

// GetCerbosResponse extracts the Cerbos CheckResources response if it was included.
// This is available when the request context included "cerbos.includeMeta": true.
func (r *AccessEvaluationResult) GetCerbosResponse() (*responsev1.CheckResourcesResponse, error) {
	if r == nil || r.AccessEvaluationResponse == nil {
		return nil, fmt.Errorf("response is nil")
	}

	contextVal, ok := r.GetContextValue("cerbos.response")
	if !ok {
		return nil, fmt.Errorf("cerbos.response not found in context")
	}

	// Convert structpb.Value to CheckResourcesResponse
	structVal := contextVal.GetStructValue()
	if structVal == nil {
		return nil, fmt.Errorf("cerbos.response is not a struct")
	}

	//TODO: replace marshalling with protobuf mapping
	jsonBytes, err := protojson.Marshal(structVal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cerbos.response: %w", err)
	}

	var cerbosResp responsev1.CheckResourcesResponse
	if err := protojson.Unmarshal(jsonBytes, &cerbosResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cerbos.response: %w", err)
	}

	return &cerbosResp, nil
}

// String returns a JSON string representation of the response.
func (r *AccessEvaluationResult) String() string {
	if r == nil || r.AccessEvaluationResponse == nil {
		return "{}"
	}
	return protojson.Format(r.AccessEvaluationResponse)
}

// MarshalJSON implements json.Marshaler.
func (r *AccessEvaluationResult) MarshalJSON() ([]byte, error) {
	if r == nil || r.AccessEvaluationResponse == nil {
		return []byte("{}"), nil
	}
	return protojson.Marshal(r.AccessEvaluationResponse)
}

// AccessEvaluationBatchResult wraps an AuthZEN batch access evaluation response.
type AccessEvaluationBatchResult struct {
	*authorizationv1.AccessEvaluationBatchResponse
}

// GetEvaluation returns the evaluation result at the specified index.
func (r *AccessEvaluationBatchResult) GetEvaluation(index int) (*AccessEvaluationResult, error) {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return nil, fmt.Errorf("response is nil")
	}

	evaluations := r.GetEvaluations()
	if index < 0 || index >= len(evaluations) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(evaluations))
	}

	return &AccessEvaluationResult{
		AccessEvaluationResponse: evaluations[index],
	}, nil
}

// AllAllowed returns true if all evaluations in the batch resulted in allow decisions.
func (r *AccessEvaluationBatchResult) AllAllowed() bool {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return false
	}

	evaluations := r.GetEvaluations()
	if len(evaluations) == 0 {
		return false
	}

	for _, eval := range evaluations {
		if !eval.GetDecision() {
			return false
		}
	}

	return true
}

// AnyAllowed returns true if at least one evaluation in the batch resulted in an allow decision.
func (r *AccessEvaluationBatchResult) AnyAllowed() bool {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return false
	}

	evaluations := r.GetEvaluations()
	for _, eval := range evaluations {
		if eval.GetDecision() {
			return true
		}
	}

	return false
}

// Count returns the number of evaluations in the batch response.
func (r *AccessEvaluationBatchResult) Count() int {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return 0
	}
	return len(r.GetEvaluations())
}

// Results returns all evaluation results as a slice of AccessEvaluationResult.
func (r *AccessEvaluationBatchResult) Results() []*AccessEvaluationResult {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return nil
	}

	evaluations := r.GetEvaluations()
	results := make([]*AccessEvaluationResult, len(evaluations))
	for i, eval := range evaluations {
		results[i] = &AccessEvaluationResult{
			AccessEvaluationResponse: eval,
		}
	}

	return results
}

// Decisions returns a slice of boolean decisions for all evaluations.
// A nil decision is returned as false.
func (r *AccessEvaluationBatchResult) Decisions() []bool {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return nil
	}

	evaluations := r.GetEvaluations()
	decisions := make([]bool, len(evaluations))
	for i, eval := range evaluations {
		decisions[i] = eval.GetDecision()
	}

	return decisions
}

// String returns a JSON string representation of the batch response.
func (r *AccessEvaluationBatchResult) String() string {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return "{}"
	}
	return protojson.Format(r.AccessEvaluationBatchResponse)
}

// MarshalJSON implements json.Marshaler.
func (r *AccessEvaluationBatchResult) MarshalJSON() ([]byte, error) {
	if r == nil || r.AccessEvaluationBatchResponse == nil {
		return []byte("{}"), nil
	}
	return protojson.Marshal(r.AccessEvaluationBatchResponse)
}

// UnmarshalJSON implements json.Unmarshaler for AccessEvaluationResult.
func (r *AccessEvaluationResult) UnmarshalJSON(data []byte) error {
	r.AccessEvaluationResponse = &authorizationv1.AccessEvaluationResponse{}
	return json.Unmarshal(data, r.AccessEvaluationResponse)
}

// UnmarshalJSON implements json.Unmarshaler for AccessEvaluationBatchResult.
func (r *AccessEvaluationBatchResult) UnmarshalJSON(data []byte) error {
	r.AccessEvaluationBatchResponse = &authorizationv1.AccessEvaluationBatchResponse{}
	return json.Unmarshal(data, r.AccessEvaluationBatchResponse)
}
