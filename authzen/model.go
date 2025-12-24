// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"fmt"

	authorizationv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/internal"
)

const (
	CerbosPrefix        = "cerbos."
	CerbosRequestID     = CerbosPrefix + "requestId"
	CerbosAuxData       = CerbosPrefix + "auxData"
	CerbosIncludeMeta   = CerbosPrefix + "includeMeta"
	CerbosPolicyVersion = CerbosPrefix + "policyVersion"
	CerbosRoles         = CerbosPrefix + "roles"
	CerbosScope         = CerbosPrefix + "scope"
)

type Subject struct {
	Obj *authorizationv1.Subject
	err error
}

func NewSubject(subjectType, id string) *Subject {
	return &Subject{
		Obj: &authorizationv1.Subject{
			Type:       subjectType,
			Id:         id,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

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

func (s *Subject) WithPropertyValue(key string, value *structpb.Value) *Subject {
	if s.Obj.Properties == nil {
		s.Obj.Properties = make(map[string]*structpb.Value)
	}

	s.Obj.Properties[key] = value
	return s
}

// WithCerbosRoles appends the set of roles to subject's existing roles.
func (s *Subject) WithCerbosRoles(roles ...string) *Subject {
	return s.WithProperty(CerbosRoles, roles)
}

// WithCerbosPolicyVersion sets the policy version for this principal.
func (s *Subject) WithCerbosPolicyVersion(version string) *Subject {
	return s.WithProperty(CerbosPolicyVersion, version)
}

// WithCerbosScope sets the scope this subject belongs to.
func (s *Subject) WithCerbosScope(scope string) *Subject {
	return s.WithProperty(CerbosScope, scope)
}

func (s *Subject) ID() string {
	return s.Obj.GetId()
}

func (s *Subject) Type() string {
	return s.Obj.GetType()
}

func (s *Subject) Proto() *authorizationv1.Subject {
	return s.Obj
}

func (s *Subject) Err() error {
	return s.err
}

func (s *Subject) Validate() error {
	if s.err != nil {
		return s.err
	}

	return internal.Validate(s.Obj)
}

type Resource struct {
	Obj *authorizationv1.Resource
	err error
}

func NewResource(resourceType, id string) *Resource {
	return &Resource{
		Obj: &authorizationv1.Resource{
			Type:       resourceType,
			Id:         id,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

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

func (r *Resource) WithPropertyValue(key string, value *structpb.Value) *Resource {
	if r.Obj.Properties == nil {
		r.Obj.Properties = make(map[string]*structpb.Value)
	}

	r.Obj.Properties[key] = value
	return r
}

func (r *Resource) WithCerbosPolicyVersion(version string) *Resource {
	return r.WithProperty("cerbos.policyVersion", version)
}

func (r *Resource) WithCerbosScope(scope string) *Resource {
	return r.WithProperty("cerbos.scope", scope)
}

func (r *Resource) ID() string {
	return r.Obj.GetId()
}

func (r *Resource) Type() string {
	return r.Obj.GetType()
}

func (r *Resource) Proto() *authorizationv1.Resource {
	return r.Obj
}

func (r *Resource) Err() error {
	return r.err
}

func (r *Resource) Validate() error {
	if r.err != nil {
		return r.err
	}

	return internal.Validate(r.Obj)
}

type Action struct {
	Obj *authorizationv1.Action
	err error
}

func NewAction(name string) *Action {
	return &Action{
		Obj: &authorizationv1.Action{
			Name:       name,
			Properties: make(map[string]*structpb.Value),
		},
	}
}

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

func (a *Action) Name() string {
	return a.Obj.GetName()
}

func (a *Action) Proto() *authorizationv1.Action {
	return a.Obj
}

func (a *Action) Err() error {
	return a.err
}

func (a *Action) Validate() error {
	if a.err != nil {
		return a.err
	}

	return internal.Validate(a.Obj)
}

type Context struct {
	data map[string]*structpb.Value
	err  error
}

func NewContext() *Context {
	return &Context{
		data: make(map[string]*structpb.Value),
	}
}

func (c *Context) WithProperty(key string, value any) *Context {
	pbVal, err := internal.ToStructPB(value)
	if err != nil {
		c.err = multierr.Append(c.err, fmt.Errorf("invalid context value for '%s': %w", key, err))
		return c
	}

	c.data[key] = pbVal
	return c
}

func (c *Context) WithPropertyValue(key string, value *structpb.Value) *Context {
	if c.data == nil {
		c.data = make(map[string]*structpb.Value)
	}

	c.data[key] = value
	return c
}

func (c *Context) WithRequestID(id string) *Context {
	return c.WithProperty(CerbosRequestID, id)
}

func (c *Context) WithAuxData(auxData *requestv1.AuxData) *Context {
	if auxData == nil {
		return c
	}
	auxDataMap := make(map[string]any)
	if jwt := auxData.GetJwt(); jwt != nil {
		auxDataMap["jwt"] = map[string]any{
			"token":    jwt.Token,
			"keySetId": jwt.KeySetId,
		}
	}
	return c.WithAuxDataMap(auxDataMap)
}

func (c *Context) WithAuxDataMap(auxData map[string]any) *Context {
	return c.WithProperty(CerbosAuxData, auxData)
}

func (c *Context) WithIncludeMeta(include bool) *Context {
	return c.WithProperty(CerbosIncludeMeta, include)
}

func (c *Context) Data() map[string]*structpb.Value {
	if c == nil {
		return nil
	}
	return c.data
}

func (c *Context) Err() error {
	return c.err
}

func (c *Context) Validate() error {
	return c.err
}
