// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"fmt"

	authorizationv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

// Subject is a container for AuthZEN subject data.
type Subject struct {
	Obj *authorizationv1.Subject
	err error
}

// NewSubject creates a new subject with the given type and ID.
func NewSubject(subjectType, id string) *Subject {
	return &Subject{
		Obj: &authorizationv1.Subject{
			Type:       subjectType,
			Id:         id,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

// WithProperty adds a property to the subject.
// It will overwrite any existing property with the same key.
func (s *Subject) WithProperty(key string, value any) *Subject {
	if s.Obj.Properties == nil {
		s.Obj.Properties = make(map[string]*structpb.Value)
	}

	pbVal, err := internal.ToStructPB(value)
	if err != nil {
		s.err = multierr.Append(s.err, fmt.Errorf("invalid property value for '%s': %w", key, err))
		return s
	}

	s.Obj.Properties[key] = pbVal
	return s
}

// WithProperties merges the given properties to subject's existing properties.
func (s *Subject) WithProperties(properties map[string]any) *Subject {
	if s.Obj.Properties == nil {
		s.Obj.Properties = make(map[string]*structpb.Value, len(properties))
	}

	for k, v := range properties {
		pbVal, err := internal.ToStructPB(v)
		if err != nil {
			s.err = multierr.Append(s.err, fmt.Errorf("invalid property value for '%s': %w", k, err))
			continue
		}
		s.Obj.Properties[k] = pbVal
	}

	return s
}

// WithCerbosRoles sets the Cerbos-specific roles property.
func (s *Subject) WithCerbosRoles(roles ...string) *Subject {
	return s.WithProperty("cerbos.roles", roles)
}

// WithCerbosPolicyVersion sets the Cerbos-specific policy version property.
func (s *Subject) WithCerbosPolicyVersion(version string) *Subject {
	return s.WithProperty("cerbos.policyVersion", version)
}

// WithCerbosScope sets the Cerbos-specific scope property.
func (s *Subject) WithCerbosScope(scope string) *Subject {
	return s.WithProperty("cerbos.scope", scope)
}

// ID returns the subject ID.
func (s *Subject) ID() string {
	return s.Obj.GetId()
}

// Type returns the subject type.
func (s *Subject) Type() string {
	return s.Obj.GetType()
}

// Proto returns the underlying protobuf object representing the subject.
func (s *Subject) Proto() *authorizationv1.Subject {
	return s.Obj
}

// Err returns any errors accumulated during the construction of the subject.
func (s *Subject) Err() error {
	return s.err
}

// Validate checks whether the subject object is valid.
func (s *Subject) Validate() error {
	if s.err != nil {
		return s.err
	}

	return internal.Validate(s.Obj)
}

// Resource is a container for AuthZEN resource data.
type Resource struct {
	Obj *authorizationv1.Resource
	err error
}

// NewResource creates a new resource with the given type and ID.
func NewResource(resourceType, id string) *Resource {
	return &Resource{
		Obj: &authorizationv1.Resource{
			Type:       resourceType,
			Id:         id,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

// WithProperty adds a property to the resource.
// It will overwrite any existing property with the same key.
func (r *Resource) WithProperty(key string, value any) *Resource {
	if r.Obj.Properties == nil {
		r.Obj.Properties = make(map[string]*structpb.Value)
	}

	pbVal, err := internal.ToStructPB(value)
	if err != nil {
		r.err = multierr.Append(r.err, fmt.Errorf("invalid property value for '%s': %w", key, err))
		return r
	}

	r.Obj.Properties[key] = pbVal
	return r
}

// WithProperties merges the given properties to resource's existing properties.
func (r *Resource) WithProperties(properties map[string]any) *Resource {
	if r.Obj.Properties == nil {
		r.Obj.Properties = make(map[string]*structpb.Value, len(properties))
	}

	for k, v := range properties {
		pbVal, err := internal.ToStructPB(v)
		if err != nil {
			r.err = multierr.Append(r.err, fmt.Errorf("invalid property value for '%s': %w", k, err))
			continue
		}
		r.Obj.Properties[k] = pbVal
	}

	return r
}

// WithCerbosPolicyVersion sets the Cerbos-specific policy version property.
func (r *Resource) WithCerbosPolicyVersion(version string) *Resource {
	return r.WithProperty("cerbos.policyVersion", version)
}

// WithCerbosScope sets the Cerbos-specific scope property.
func (r *Resource) WithCerbosScope(scope string) *Resource {
	return r.WithProperty("cerbos.scope", scope)
}

// ID returns the resource ID.
func (r *Resource) ID() string {
	return r.Obj.GetId()
}

// Type returns the resource type.
func (r *Resource) Type() string {
	return r.Obj.GetType()
}

// Proto returns the underlying protobuf object representing the resource.
func (r *Resource) Proto() *authorizationv1.Resource {
	return r.Obj
}

// Err returns any errors accumulated during the construction of the resource.
func (r *Resource) Err() error {
	return r.err
}

// Validate checks whether the resource is valid.
func (r *Resource) Validate() error {
	if r.err != nil {
		return r.err
	}

	return internal.Validate(r.Obj)
}

// Action is a container for AuthZEN action data.
type Action struct {
	Obj *authorizationv1.Action
	err error
}

// NewAction creates a new action with the given name.
func NewAction(name string) *Action {
	return &Action{
		Obj: &authorizationv1.Action{
			Name:       name,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

// WithProperty adds a property to the action.
// It will overwrite any existing property with the same key.
func (a *Action) WithProperty(key string, value any) *Action {
	if a.Obj.Properties == nil {
		a.Obj.Properties = make(map[string]*structpb.Value)
	}

	pbVal, err := internal.ToStructPB(value)
	if err != nil {
		a.err = multierr.Append(a.err, fmt.Errorf("invalid property value for '%s': %w", key, err))
		return a
	}

	a.Obj.Properties[key] = pbVal
	return a
}

// WithProperties merges the given properties to action's existing properties.
func (a *Action) WithProperties(properties map[string]any) *Action {
	if a.Obj.Properties == nil {
		a.Obj.Properties = make(map[string]*structpb.Value, len(properties))
	}

	for k, v := range properties {
		pbVal, err := internal.ToStructPB(v)
		if err != nil {
			a.err = multierr.Append(a.err, fmt.Errorf("invalid property value for '%s': %w", k, err))
			continue
		}
		a.Obj.Properties[k] = pbVal
	}

	return a
}

// Name returns the action name.
func (a *Action) Name() string {
	return a.Obj.GetName()
}

// Proto returns the underlying protobuf object representing the action.
func (a *Action) Proto() *authorizationv1.Action {
	return a.Obj
}

// Err returns any errors accumulated during the construction of the action.
func (a *Action) Err() error {
	return a.err
}

// Validate checks whether the action is valid.
func (a *Action) Validate() error {
	if a.err != nil {
		return a.err
	}

	return internal.Validate(a.Obj)
}

// Context is a helper for building AuthZEN context data.
type Context struct {
	data map[string]*structpb.Value
	err  error
}

// NewContext creates a new context.
func NewContext() *Context {
	return &Context{
		data: make(map[string]*structpb.Value),
	}
}

// WithProperty adds a property to the context.
// It will overwrite any existing property with the same key.
func (c *Context) WithProperty(key string, value any) *Context {
	pbVal, err := internal.ToStructPB(value)
	if err != nil {
		c.err = multierr.Append(c.err, fmt.Errorf("invalid context value for '%s': %w", key, err))
		return c
	}

	c.data[key] = pbVal
	return c
}

// WithRequestID sets the Cerbos-specific request ID in the context.
func (c *Context) WithRequestID(id string) *Context {
	return c.WithProperty("cerbos.requestId", id)
}

// WithAuxData sets the Cerbos-specific auxiliary data in the context.
func (c *Context) WithAuxData(auxData map[string]any) *Context {
	return c.WithProperty("cerbos.auxData", auxData)
}

// WithIncludeMeta sets whether to include Cerbos metadata in the response.
func (c *Context) WithIncludeMeta(include bool) *Context {
	return c.WithProperty("cerbos.includeMeta", include)
}

// Data returns the context data map.
func (c *Context) Data() map[string]*structpb.Value {
	return c.data
}

// Err returns any errors accumulated during the construction of the context.
func (c *Context) Err() error {
	return c.err
}

// Validate checks whether the context is valid.
func (c *Context) Validate() error {
	return c.err
}
