// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"context"
	"log"
	"time"

	"github.com/cerbos/cerbos-sdk-go/authzen"
	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

// ExampleClient_AccessEvaluation demonstrates how to evaluate a single access request using the AuthZEN API.
func ExampleClient_AccessEvaluation() {
	c, err := authzen.NewClient("https://pdp.example.com:3592")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithCerbosPolicyVersion("20210210").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("team", "design")

	resource := authzen.NewResource("leave_request", "XX125").
		WithCerbosPolicyVersion("20210210").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("id", "XX125").
		WithProperty("owner", "john").
		WithProperty("team", "design")

	action := authzen.NewAction("view:public")

	result, err := c.AccessEvaluation(context.TODO(), subject, resource, action, nil)
	if err != nil {
		log.Fatalf("Failed to evaluate access: %v", err)
	}

	if result.IsAllowed() {
		log.Println("Action view:public is allowed on resource XX125")
	}
}

// ExampleClient_IsAllowed demonstrates how to check if an action is allowed using the simplified IsAllowed method.
func ExampleClient_IsAllowed() {
	c, err := authzen.NewClient("https://pdp.example.com:3592")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithProperty("department", "marketing")

	resource := authzen.NewResource("leave_request", "XX125").
		WithProperty("owner", "john")

	allowed, err := c.IsAllowed(context.TODO(), subject, resource, "view", nil)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is john allowed to view leave_request XX125: %t", allowed)
}

// ExampleSubjectCtx_IsAllowed demonstrates how to use the subject context for multiple checks.
func ExampleSubjectCtx_IsAllowed() {
	c, err := authzen.NewClient("https://pdp.example.com:3592")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Create a subject context for reuse across multiple checks
	sc := c.WithSubject(authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithProperty("department", "marketing"))

	resource := authzen.NewResource("leave_request", "XX125").
		WithProperty("owner", "john")

	allowed, err := sc.IsAllowed(context.TODO(), resource, "view")
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is john allowed to view leave_request XX125: %t", allowed)
}

// ExampleFromCerbosPrincipal demonstrates how to convert Cerbos models to AuthZEN models.
func ExampleFromCerbosPrincipal() {
	// Create a Cerbos Principal
	principal := cerbos.NewPrincipal("john").
		WithRoles("employee", "manager").
		WithPolicyVersion("20210210").
		WithAttributes(map[string]any{
			"department": "marketing",
			"geography":  "GB",
		})

	// Convert to AuthZEN Subject
	subject, err := authzen.FromCerbosPrincipal(principal)
	if err != nil {
		log.Fatalf("Failed to convert principal: %v", err)
	}

	log.Printf("Converted subject ID: %s", subject.Proto().GetId())
}

// ExampleFromCerbosResource demonstrates how to convert a Cerbos Resource to an AuthZEN Resource.
func ExampleFromCerbosResource() {
	// Create a Cerbos Resource
	resource := cerbos.NewResource("leave_request", "XX125").
		WithPolicyVersion("20210210").
		WithAttributes(map[string]any{
			"department": "marketing",
			"owner":      "john",
		})

	// Convert to AuthZEN Resource
	authzenResource, err := authzen.FromCerbosResource(resource)
	if err != nil {
		log.Fatalf("Failed to convert resource: %v", err)
	}

	log.Printf("Converted resource type: %s, ID: %s", authzenResource.Proto().GetType(), authzenResource.Proto().GetId())
}

// ExampleClient_AccessEvaluations demonstrates how to evaluate multiple access requests in a batch.
func ExampleClient_AccessEvaluations() {
	c, err := authzen.NewClient("https://pdp.example.com:3592")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithProperty("department", "marketing")

	batch := &authzen.BatchEvaluationRequest{
		DefaultSubject: subject,
		DefaultContext: authzen.NewContext().WithIncludeMeta(false),
		Semantics:      authzen.ExecuteAll,
		Evaluations: []authzen.BatchEvaluation{
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithProperty("owner", "john"),
				Action: authzen.NewAction("view"),
			},
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithProperty("owner", "john"),
				Action: authzen.NewAction("approve"),
			},
			{
				Resource: authzen.NewResource("leave_request", "XX225").
					WithProperty("owner", "mary"),
				Action: authzen.NewAction("view"),
			},
		},
	}

	result, err := c.AccessEvaluations(context.TODO(), batch)
	if err != nil {
		log.Fatalf("Failed to evaluate batch: %v", err)
	}

	for i := 0; i < result.Count(); i++ {
		eval, err := result.GetEvaluation(i)
		if err != nil {
			log.Fatalf("Failed to get evaluation %d: %v", i, err)
		}
		log.Printf("Evaluation %d: allowed=%t", i, eval.IsAllowed())
	}
}

// ExampleNewGRPCClient demonstrates how to create a gRPC client for AuthZEN.
func ExampleNewGRPCClient() {
	// Create a gRPC client with TLS (default)
	c, err := authzen.NewGRPCClient("localhost:3593", cerbos.WithTLSInsecure())
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithProperty("department", "marketing")

	resource := authzen.NewResource("leave_request", "XX125").
		WithProperty("owner", "john")

	allowed, err := c.IsAllowed(context.TODO(), subject, resource, "view", nil)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is john allowed to view leave_request XX125: %t", allowed)
}

// ExampleNewGRPCClient_plaintext demonstrates how to create a gRPC client without TLS.
func ExampleNewGRPCClient_plaintext() {
	// Create a gRPC client without TLS (plaintext)
	c, err := authzen.NewGRPCClient("localhost:3593", cerbos.WithPlaintext())
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithProperty("department", "marketing")

	resource := authzen.NewResource("leave_request", "XX125").
		WithProperty("owner", "john")

	allowed, err := c.IsAllowed(context.TODO(), subject, resource, "view", nil)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is john allowed to view leave_request XX125: %t", allowed)
}

// ExampleNewGRPCClient_withOptions demonstrates how to configure the gRPC client with various options.
func ExampleNewGRPCClient_withOptions() {
	c, err := authzen.NewGRPCClient(
		"localhost:3593",
		cerbos.WithTLSInsecure(),
		cerbos.WithConnectTimeout(5*time.Second),
		cerbos.WithMaxRetries(3),
		cerbos.WithUserAgent("my-app/1.0"),
	)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee")

	resource := authzen.NewResource("leave_request", "XX125")

	allowed, err := c.IsAllowed(context.TODO(), subject, resource, "view", nil)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is john allowed to view leave_request XX125: %t", allowed)
}
