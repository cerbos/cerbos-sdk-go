// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

// fromStructPB converts a structpb.Value to a Go value.
func fromStructPB(v *structpb.Value) any {
	if v == nil {
		return nil
	}
	return v.AsInterface()
}

// PrincipalToSubject converts a Cerbos Principal to an AuthZEN Subject.
// The mapping follows the AuthZEN specification:
// - principal.id -> subject.id
// - principal.roles -> subject.properties["cerbos.roles"]
// - principal.policyVersion -> subject.properties["cerbos.policyVersion"]
// - principal.scope -> subject.properties["cerbos.scope"]
// - principal.attr.* -> subject.properties.*.
func PrincipalToSubject(principal *cerbos.Principal) (*Subject, error) {
	if principal == nil {
		return nil, fmt.Errorf("principal cannot be nil")
	}

	p := principal.Proto()
	subject := NewSubject("user", p.GetId())

	// Add Cerbos-specific properties
	if len(p.GetRoles()) > 0 {
		subject.WithCerbosRoles(p.GetRoles()...)
	}

	if p.GetPolicyVersion() != "" {
		subject.WithCerbosPolicyVersion(p.GetPolicyVersion())
	}

	if p.GetScope() != "" {
		subject.WithCerbosScope(p.GetScope())
	}

	// Add all other attributes as properties
	for k, v := range p.GetAttr() {
		val := fromStructPB(v)
		subject.WithProperty(k, val)
	}

	if err := subject.Err(); err != nil {
		return nil, err
	}

	return subject, nil
}

// SubjectToPrincipal converts an AuthZEN Subject to a Cerbos Principal.
// The mapping follows the AuthZEN specification in reverse:
// - subject.id -> principal.id
// - subject.properties["cerbos.roles"] -> principal.roles
// - subject.properties["cerbos.policyVersion"] -> principal.policyVersion
// - subject.properties["cerbos.scope"] -> principal.scope
// - subject.properties.* (non-cerbos) -> principal.attr.*.
func SubjectToPrincipal(subject *Subject) (*cerbos.Principal, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject cannot be nil")
	}

	s := subject.Proto()
	principal := cerbos.NewPrincipal(s.GetId())

	props := s.GetProperties()

	// Extract Cerbos-specific properties
	if rolesVal, ok := props["cerbos.roles"]; ok {
		roles, err := extractStringSlice(rolesVal)
		if err != nil {
			return nil, fmt.Errorf("invalid cerbos.roles: %w", err)
		}
		principal.WithRoles(roles...)
	}

	if versionVal, ok := props["cerbos.policyVersion"]; ok {
		version := versionVal.GetStringValue()
		if version != "" {
			principal.WithPolicyVersion(version)
		}
	}

	if scopeVal, ok := props["cerbos.scope"]; ok {
		scope := scopeVal.GetStringValue()
		if scope != "" {
			principal.WithScope(scope)
		}
	}

	// Add all non-Cerbos-specific properties as attributes
	for k, v := range props {
		if !isCerbosProperty(k) {
			val := fromStructPB(v)
			principal.WithAttr(k, val)
		}
	}

	if err := principal.Err(); err != nil {
		return nil, err
	}

	return principal, nil
}

// ResourceToAuthZEN converts a Cerbos Resource to an AuthZEN Resource.
// The mapping follows the AuthZEN specification:
// - resource.kind -> resource.type
// - resource.id -> resource.id
// - resource.policyVersion -> resource.properties["cerbos.policyVersion"]
// - resource.scope -> resource.properties["cerbos.scope"]
// - resource.attr.* -> resource.properties.*.
func ResourceToAuthZEN(resource *cerbos.Resource) (*Resource, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}

	r := resource.Proto()
	authzenResource := NewResource(r.GetKind(), r.GetId())

	// Add Cerbos-specific properties
	if r.GetPolicyVersion() != "" {
		authzenResource.WithCerbosPolicyVersion(r.GetPolicyVersion())
	}

	if r.GetScope() != "" {
		authzenResource.WithCerbosScope(r.GetScope())
	}

	// Add all other attributes as properties
	for k, v := range r.GetAttr() {
		val := fromStructPB(v)
		authzenResource.WithProperty(k, val)
	}

	if err := authzenResource.Err(); err != nil {
		return nil, err
	}

	return authzenResource, nil
}

// AuthZENToResource converts an AuthZEN Resource to a Cerbos Resource.
// The mapping follows the AuthZEN specification in reverse:
// - resource.type -> resource.kind
// - resource.id -> resource.id
// - resource.properties["cerbos.policyVersion"] -> resource.policyVersion
// - resource.properties["cerbos.scope"] -> resource.scope
// - resource.properties.* (non-cerbos) -> resource.attr.*.
//
//nolint:revive // AuthZEN is the standard name
func AuthZENToResource(resource *Resource) (*cerbos.Resource, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}

	r := resource.Proto()
	cerbosResource := cerbos.NewResource(r.GetType(), r.GetId())

	props := r.GetProperties()

	// Extract Cerbos-specific properties
	if versionVal, ok := props["cerbos.policyVersion"]; ok {
		version := versionVal.GetStringValue()
		if version != "" {
			cerbosResource.WithPolicyVersion(version)
		}
	}

	if scopeVal, ok := props["cerbos.scope"]; ok {
		scope := scopeVal.GetStringValue()
		if scope != "" {
			cerbosResource.WithScope(scope)
		}
	}

	// Add all non-Cerbos-specific properties as attributes
	for k, v := range props {
		if !isCerbosProperty(k) {
			val := fromStructPB(v)
			cerbosResource.WithAttr(k, val)
		}
	}

	if err := cerbosResource.Err(); err != nil {
		return nil, err
	}

	return cerbosResource, nil
}

// ActionToAuthZEN converts a Cerbos action string to an AuthZEN Action.
func ActionToAuthZEN(action string) *Action {
	return NewAction(action)
}

// AuthZENToAction converts an AuthZEN Action to a Cerbos action string.
//
//nolint:revive // AuthZEN is the standard name
func AuthZENToAction(action *Action) string {
	if action == nil {
		return ""
	}
	return action.Name()
}

// BuildCerbosCheckResourceRequest builds a Cerbos CheckResources request from AuthZEN entities.
// This is useful for converting AuthZEN requests to Cerbos format internally.
func BuildCerbosCheckResourceRequest(subject *Subject, resource *Resource, action *Action) (*enginev1.Principal, *enginev1.Resource, string, error) {
	principal, err := SubjectToPrincipal(subject)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to convert subject: %w", err)
	}

	cerbosResource, err := AuthZENToResource(resource)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to convert resource: %w", err)
	}

	actionStr := AuthZENToAction(action)
	if actionStr == "" {
		return nil, nil, "", fmt.Errorf("action cannot be empty")
	}

	return principal.Proto(), cerbosResource.Proto(), actionStr, nil
}

// Helper functions

func isCerbosProperty(key string) bool {
	return len(key) >= 7 && key[:7] == "cerbos."
}

func extractStringSlice(v *structpb.Value) ([]string, error) {
	list := v.GetListValue()
	if list == nil {
		return nil, fmt.Errorf("expected list value")
	}

	values := list.GetValues()
	result := make([]string, len(values))
	for i, val := range values {
		str := val.GetStringValue()
		if str == "" {
			return nil, fmt.Errorf("expected string value at index %d", i)
		}
		result[i] = str
	}

	return result, nil
}
