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

// FromCerbosPrincipal converts a Cerbos Principal to an AuthZEN Subject.
// The mapping follows the AuthZEN specification:
// - principal.id -> subject.id
// - principal.roles -> subject.properties["cerbos.roles"]
// - principal.policyVersion -> subject.properties["cerbos.policyVersion"]
// - principal.scope -> subject.properties["cerbos.scope"]
// - principal.attr.* -> subject.properties.*.
func FromCerbosPrincipal(principal *cerbos.Principal) (*Subject, error) {
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

// ToCerbosPrincipal converts an AuthZEN Subject to a Cerbos Principal.
// The mapping follows the AuthZEN specification in reverse:
// - subject.id -> principal.id
// - subject.properties["cerbos.roles"] -> principal.roles
// - subject.properties["cerbos.policyVersion"] -> principal.policyVersion
// - subject.properties["cerbos.scope"] -> principal.scope
// - subject.properties.* (non-cerbos) -> principal.attr.*.
func ToCerbosPrincipal(subject *Subject) (*cerbos.Principal, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject cannot be nil")
	}

	s := subject.Proto()
	principal := cerbos.NewPrincipal(s.GetId())

	props := s.GetProperties()

	if rolesVal, ok := props["cerbos.roles"]; ok {
		roles, err := extractStringSlice(rolesVal)
		if err != nil {
			return nil, fmt.Errorf("invalid cerbos.roles: %w", err)
		}
		principal.WithRoles(roles...)
	}

	if version := props["cerbos.policyVersion"].GetStringValue(); version != "" {
		principal.WithPolicyVersion(version)
	}

	if scope := props["cerbos.scope"].GetStringValue(); scope != "" {
		principal.WithScope(scope)
	}

	for k, v := range props {
		if !isCerbosProperty(k) {
			principal.WithAttrValue(k, v)
		}
	}

	if err := principal.Err(); err != nil {
		return nil, err
	}

	return principal, nil
}

// FromCerbosResource converts a Cerbos Resource to an AuthZEN Resource.
// The mapping follows the AuthZEN specification:
// - resource.kind -> resource.type
// - resource.id -> resource.id
// - resource.policyVersion -> resource.properties["cerbos.policyVersion"]
// - resource.scope -> resource.properties["cerbos.scope"]
// - resource.attr.* -> resource.properties.*.
func FromCerbosResource(resource *cerbos.Resource) (*Resource, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}

	r := resource.Proto()
	authzenResource := NewResource(r.GetKind(), r.GetId())

	if r.GetPolicyVersion() != "" {
		authzenResource.WithCerbosPolicyVersion(r.GetPolicyVersion())
	}

	if r.GetScope() != "" {
		authzenResource.WithCerbosScope(r.GetScope())
	}

	for k, v := range r.GetAttr() {
		authzenResource.WithProperty(k, v)
	}

	if err := authzenResource.Err(); err != nil {
		return nil, err
	}

	return authzenResource, nil
}

// ToCerbosResource converts an AuthZEN Resource to a Cerbos Resource.
// The mapping follows the AuthZEN specification in reverse:
// - resource.type -> resource.kind
// - resource.id -> resource.id
// - resource.properties["cerbos.policyVersion"] -> resource.policyVersion
// - resource.properties["cerbos.scope"] -> resource.scope
// - resource.properties.* (non-cerbos) -> resource.attr.*.
func ToCerbosResource(resource *Resource) (*cerbos.Resource, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}

	r := resource.Proto()
	cerbosResource := cerbos.NewResource(r.GetType(), r.GetId())

	props := r.GetProperties()

	if version := props["cerbos.policyVersion"].GetStringValue(); version != "" {
		cerbosResource.WithPolicyVersion(version)
	}

	if scope := props["cerbos.scope"].GetStringValue(); scope != "" {
		cerbosResource.WithScope(scope)
	}

	for k, v := range props {
		if !isCerbosProperty(k) {
			cerbosResource.WithAttrValue(k, v)
		}
	}

	if err := cerbosResource.Err(); err != nil {
		return nil, err
	}

	return cerbosResource, nil
}

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
