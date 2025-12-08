// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/authzen"
	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

func TestNewClient(t *testing.T) {
	t.Run("valid URL", func(t *testing.T) {
		client, err := authzen.NewClient("https://localhost:3592")
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("empty URL", func(t *testing.T) {
		client, err := authzen.NewClient("")
		require.Error(t, err)
		require.Nil(t, client)
	})

	t.Run("invalid URL", func(t *testing.T) {
		client, err := authzen.NewClient("://invalid")
		require.Error(t, err)
		require.Nil(t, client)
	})

	t.Run("with custom headers", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom-Header": "custom-value",
		}
		client, err := authzen.NewClient("https://localhost:3592", authzen.WithHeaders(headers))
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestSubject(t *testing.T) {
	t.Run("create with basic fields", func(t *testing.T) {
		subject := authzen.NewSubject("user", "alice")
		require.NotNil(t, subject)
		assert.Equal(t, "user", subject.Type())
		assert.Equal(t, "alice", subject.ID())
		assert.NoError(t, subject.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		subject := authzen.NewSubject("user", "alice").
			WithProperty("department", "engineering").
			WithProperty("level", 5)

		require.NotNil(t, subject)
		assert.NoError(t, subject.Err())
		assert.NotNil(t, subject.Proto().GetProperties())
	})

	t.Run("with Cerbos-specific properties", func(t *testing.T) {
		subject := authzen.NewSubject("user", "alice").
			WithCerbosRoles("admin", "user").
			WithCerbosPolicyVersion("v1.0").
			WithCerbosScope("acme.corp")

		require.NotNil(t, subject)
		assert.NoError(t, subject.Err())

		props := subject.Proto().GetProperties()
		assert.Contains(t, props, "cerbos.roles")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}

func TestResource(t *testing.T) {
	t.Run("create with basic fields", func(t *testing.T) {
		resource := authzen.NewResource("document", "doc123")
		require.NotNil(t, resource)
		assert.Equal(t, "document", resource.Type())
		assert.Equal(t, "doc123", resource.ID())
		assert.NoError(t, resource.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		resource := authzen.NewResource("document", "doc123").
			WithProperty("owner", "alice").
			WithProperty("public", true)

		require.NotNil(t, resource)
		assert.NoError(t, resource.Err())
		assert.NotNil(t, resource.Proto().GetProperties())
	})

	t.Run("with Cerbos properties", func(t *testing.T) {
		resource := authzen.NewResource("document", "doc123").
			WithCerbosPolicyVersion("v1.0").
			WithCerbosScope("acme.corp")

		require.NotNil(t, resource)
		assert.NoError(t, resource.Err())

		props := resource.Proto().GetProperties()
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}

func TestAction(t *testing.T) {
	t.Run("create with name", func(t *testing.T) {
		action := authzen.NewAction("read")
		require.NotNil(t, action)
		assert.Equal(t, "read", action.Name())
		assert.NoError(t, action.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		action := authzen.NewAction("read").
			WithProperty("scope", "full")

		require.NotNil(t, action)
		assert.NoError(t, action.Err())
		assert.NotNil(t, action.Proto().GetProperties())
	})
}

func TestContext(t *testing.T) {
	t.Run("create empty", func(t *testing.T) {
		ctx := authzen.NewContext()
		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
	})

	t.Run("with request ID", func(t *testing.T) {
		ctx := authzen.NewContext().
			WithRequestID("test-request-123")

		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
		assert.Contains(t, ctx.Data(), "cerbos.requestId")
	})

	t.Run("with include meta", func(t *testing.T) {
		ctx := authzen.NewContext().
			WithIncludeMeta(true)

		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
		assert.Contains(t, ctx.Data(), "cerbos.includeMeta")
	})
}

func TestFromCerbosPrincipal(t *testing.T) {
	t.Run("convert basic principal", func(t *testing.T) {
		principal := cerbos.NewPrincipal("alice", "admin", "user")
		subject, err := authzen.FromCerbosPrincipal(principal)

		require.NoError(t, err)
		require.NotNil(t, subject)
		assert.Equal(t, "alice", subject.ID())
		assert.Equal(t, "user", subject.Type())
	})

	t.Run("convert principal with attributes", func(t *testing.T) {
		principal := cerbos.NewPrincipal("alice", "admin").
			WithAttr("department", "engineering").
			WithAttr("level", 5).
			WithPolicyVersion("v1.0").
			WithScope("acme.corp")

		subject, err := authzen.FromCerbosPrincipal(principal)

		require.NoError(t, err)
		require.NotNil(t, subject)

		props := subject.Proto().GetProperties()
		assert.Contains(t, props, "department")
		assert.Contains(t, props, "level")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
		assert.Contains(t, props, "cerbos.roles")
	})

	t.Run("nil principal", func(t *testing.T) {
		subject, err := authzen.FromCerbosPrincipal(nil)
		require.Error(t, err)
		require.Nil(t, subject)
	})
}

func TestFromCerbosResource(t *testing.T) {
	t.Run("convert basic resource", func(t *testing.T) {
		resource := cerbos.NewResource("document", "doc123")
		authzenResource, err := authzen.FromCerbosResource(resource)

		require.NoError(t, err)
		require.NotNil(t, authzenResource)
		assert.Equal(t, "document", authzenResource.Type())
		assert.Equal(t, "doc123", authzenResource.ID())
	})

	t.Run("convert resource with attributes", func(t *testing.T) {
		resource := cerbos.NewResource("document", "doc123").
			WithAttr("owner", "alice").
			WithAttr("public", true).
			WithPolicyVersion("v1.0").
			WithScope("acme.corp")

		authzenResource, err := authzen.FromCerbosResource(resource)

		require.NoError(t, err)
		require.NotNil(t, authzenResource)

		props := authzenResource.Proto().GetProperties()
		assert.Contains(t, props, "owner")
		assert.Contains(t, props, "public")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}

func TestAccessEvaluation(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/access/v1/evaluation", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Return a mock response
		response := map[string]any{
			"decision": true,
			"context": map[string]any{
				"test": "value",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := authzen.NewClient(server.URL)
	require.NoError(t, err)

	subject := authzen.NewSubject("user", "alice").
		WithCerbosRoles("admin")
	resource := authzen.NewResource("document", "doc123")
	action := authzen.NewAction("read")

	result, err := client.AccessEvaluation(context.Background(), subject, resource, action, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsAllowed())
}

func TestAccessEvaluations(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/access/v1/evaluations", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Return a mock batch response
		response := map[string]any{
			"evaluations": []map[string]any{
				{"decision": true},
				{"decision": false},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := authzen.NewClient(server.URL)
	require.NoError(t, err)

	batchReq := &authzen.BatchEvaluationRequest{
		DefaultSubject:  authzen.NewSubject("user", "alice"),
		DefaultResource: authzen.NewResource("document", "doc123"),
		Evaluations: []authzen.BatchEvaluation{
			{Action: authzen.NewAction("read")},
			{Action: authzen.NewAction("delete")},
		},
		Semantics: authzen.ExecuteAll,
	}

	result, err := client.AccessEvaluations(context.Background(), batchReq)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 2, result.Count())
	assert.False(t, result.AllAllowed())
	assert.True(t, result.AnyAllowed())

	decisions := result.Decisions()
	assert.Equal(t, []bool{true, false}, decisions)
}

func TestAccessEvaluationResult(t *testing.T) {
	t.Run("IsAllowed with nil response", func(t *testing.T) {
		result := &authzen.AccessEvaluationResult{}
		assert.False(t, result.IsAllowed())
	})
}

func TestGetMetadata(t *testing.T) {
	// Create a test server
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/authzen-configuration", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		response := authzen.MetadataResponse{
			PolicyDecisionPoint:       server.URL,
			AccessEvaluationEndpoint:  server.URL + "/access/v1/evaluation",
			AccessEvaluationsEndpoint: server.URL + "/access/v1/evaluations",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := authzen.NewClient(server.URL)
	require.NoError(t, err)

	metadata, err := client.GetMetadata(context.Background())
	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, server.URL, metadata.PolicyDecisionPoint)
	assert.Contains(t, metadata.AccessEvaluationEndpoint, "/access/v1/evaluation")
}

// Example usage.
func ExampleClient_AccessEvaluation() {
	client, _ := authzen.NewClient("https://localhost:3592")

	subject := authzen.NewSubject("user", "alice").
		WithCerbosRoles("employee").
		WithProperty("department", "engineering")

	resource := authzen.NewResource("document", "doc123").
		WithProperty("owner", "alice")

	action := authzen.NewAction("read")

	ctx := authzen.NewContext().
		WithRequestID("my-request-id").
		WithIncludeMeta(true)

	result, _ := client.AccessEvaluation(context.Background(), subject, resource, action, ctx)

	_ = result.IsAllowed()
}

func ExampleClient_AccessEvaluations() {
	client, _ := authzen.NewClient("https://localhost:3592")

	// Define defaults that apply to all evaluations
	defaultSubject := authzen.NewSubject("user", "alice")
	defaultResource := authzen.NewResource("document", "doc123")

	batchReq := &authzen.BatchEvaluationRequest{
		DefaultSubject:  defaultSubject,
		DefaultResource: defaultResource,
		Evaluations: []authzen.BatchEvaluation{
			{Action: authzen.NewAction("read")},
			{Action: authzen.NewAction("write")},
			{Action: authzen.NewAction("delete")},
		},
		Semantics: authzen.ExecuteAll,
	}

	result, _ := client.AccessEvaluations(context.Background(), batchReq)

	_ = result.AllAllowed()
	_ = result.Decisions()
}
