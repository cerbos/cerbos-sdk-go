// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos_test

import (
	"context"
	"log"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

// ExampleNew demonstrates how to instantiate a new client and make a request.
func ExampleNew() {
	// A client that connects to Cerbos over a Unix domain socket using a CA certificate to validate the server TLS certificates.
	c, err := cerbos.New("unix:/var/sock/cerbos", cerbos.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	allowed, err := c.IsAllowed(
		context.TODO(),
		cerbos.NewPrincipal("sally").WithRoles("user"),
		cerbos.NewResource("album:object", "A001"),
		"view",
	)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is Sally allowed to view album A001: %t", allowed)
}

// ExampleClient_CheckResources demonstrates how to make a CheckResources API request.
func ExampleClient_CheckResources() {
	c, err := cerbos.New("dns:///cerbos.ns.svc.cluster.local:3593", cerbos.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	cc := c.WithPrincipal(cerbos.NewPrincipal("john").
		WithRoles("employee").
		WithPolicyVersion("20210210").
		WithAttributes(map[string]any{
			"department": "marketing",
			"geography":  "GB",
			"team":       "design",
		}))

	resources := cerbos.NewResourceBatch().
		Add(cerbos.
			NewResource("leave_request", "XX125").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]any{
				"department": "marketing",
				"geography":  "GB",
				"id":         "XX125",
				"owner":      "john",
				"team":       "design",
			}), "view:public", "defer").
		Add(cerbos.
			NewResource("leave_request", "XX225").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]any{
				"department": "engineering",
				"geography":  "GB",
				"id":         "XX225",
				"owner":      "mary",
				"team":       "frontend",
			}), "approve")

	result, err := cc.CheckResources(context.TODO(), resources)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	resXX125 := result.GetResource("XX125", cerbos.MatchResourcePolicyVersion("20210210"))
	if resXX125.IsAllowed("view:public") {
		log.Println("Action view:public is allowed on resource XX125")
	}
}

// ExampleNewAdminClient demonstrates how to instantiate a new admin client and make a request.
func ExampleNewAdminClient() {
	// Create an admin client using the credentials stored in environment variables or netrc.
	ac, err := cerbos.NewAdminClient("10.1.2.3:3593", cerbos.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create admin client: %v", err)
	}

	policy := cerbos.NewResourcePolicy("album:comments", "default").
		WithDerivedRolesImports("album_derived_roles").
		AddResourceRules(
			cerbos.NewAllowResourceRule("view").
				WithDerivedRoles("owners").
				WithCondition(
					cerbos.MatchAllOf(
						cerbos.MatchExpr(`request.resource.attr.status == "unmoderated"`),
						cerbos.MatchExpr(`request.resource.attr.user_status == "anonymous"`),
					),
				),
		)

	if err := ac.AddOrUpdatePolicy(context.TODO(), cerbos.NewPolicySet().AddResourcePolicies(policy)); err != nil {
		log.Fatalf("Failed to add policy: %v", err)
	}
}
