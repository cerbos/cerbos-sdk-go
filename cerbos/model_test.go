// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package cerbos_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

const (
	actionApprove       = "approve"
	actionCreate        = "create"
	id                  = "XX125"
	kind                = "leave_request"
	derivedRolesName    = "my_derived_roles"
	exportVariablesName = "my_variables"
	ref                 = "cerbos:///principal.json"
	roleName            = "employee_that_owns_the_record"
	ruleName            = "rule-001"
	principal           = "bugs_bunny"
	resource            = "leave_request"
	scope               = "acme"
	version             = "v1"
	variableName        = "foo"
	variableExpr        = "42"

	attrKey    = "department"
	attrValue  = "marketing"
	boolAttr   = true
	doubleAttr = 1.5
	stringAttr = "stringAttr"

	boolAttrKey   = "boolAttr"
	doubleAttrKey = "doubleAttr"
	listAttrKey   = "listAttr"
	mapAttrKey    = "mapAttr"
	stringAttrKey = "stringAttr"
)

var (
	attributes = map[string]any{
		boolAttrKey:   boolAttr,
		doubleAttrKey: doubleAttr,
		stringAttrKey: stringAttr,
		listAttrKey:   listAttr,
		mapAttrKey:    mapAttr,
	}
	listAttr = []any{"a", "b", "c"}
	mapAttr  = map[string]any{"a": "a", "b": "b", "c": "c"}
	roles    = []string{"user", "principal", "president"}
)

func TestBuilders(t *testing.T) {
	t.Run("DerivedRoles", func(t *testing.T) {
		dr := newDerivedRoles(t)
		require.NoError(t, dr.Validate())
		cmpDerivedRoles(t, dr)
	})
	t.Run("ExportVariables", func(t *testing.T) {
		ev := newExportVariables(t)
		require.NoError(t, ev.Validate())
		cmpExportVariables(t, ev)
	})
	t.Run("Principal", func(t *testing.T) {
		p := newPrincipal(t)
		require.NoError(t, p.Validate())
		cmpPrincipal(t, p)
	})
	t.Run("Resource", func(t *testing.T) {
		r := newResource(t)
		require.NoError(t, r.Validate())
		cmpResource(t, r)
	})
	t.Run("Schema", func(t *testing.T) {
		s := newSchema(t)
		require.NoError(t, s.Validate())
		cmpSchema(t, s)
	})

	t.Run("PrincipalPolicy", func(t *testing.T) {
		pp := newPrincipalPolicy(t)
		require.NoError(t, pp.Validate())
		cmpPrincipalPolicy(t, pp)
	})
	t.Run("ResourcePolicy", func(t *testing.T) {
		rp := newResourcePolicy(t)
		require.NoError(t, rp.Validate())
		cmpResourcePolicy(t, rp)
	})

	t.Run("PrincipalRule", func(t *testing.T) {
		pr := newPrincipalRule(t)
		require.NoError(t, pr.Validate())
		cmpPrincipalRule(t, pr)
	})
	t.Run("ResourceRule", func(t *testing.T) {
		rr := newResourceRule(t)
		require.NoError(t, rr.Validate())
		cmpResourceRule(t, rr)
	})

	t.Run("PolicySet", func(t *testing.T) {
		ps := newPolicySet(t)
		require.NoError(t, ps.Validate())
		cmpPolicySet(t, ps)
	})
}

func cmpDerivedRoles(t *testing.T, dr *cerbos.DerivedRoles) {
	t.Helper()

	require.Equal(t, derivedRolesName, dr.Obj.Name)
	require.Equal(t, roleName, dr.Obj.Definitions[0].Name)
	for i, role := range roles {
		require.Equal(t, role, dr.Obj.Definitions[0].ParentRoles[i])
	}
	require.Equal(t, []string{exportVariablesName}, dr.Obj.Variables.Import)
	require.Equal(t, map[string]string{variableName: variableExpr}, dr.Obj.Variables.Local)
}

func cmpExportVariables(t *testing.T, ev *cerbos.ExportVariables) {
	t.Helper()

	require.Equal(t, exportVariablesName, ev.Obj.Name)
	require.Equal(t, map[string]string{variableName: variableExpr}, ev.Obj.Definitions)
}

func cmpPrincipal(t *testing.T, p *cerbos.Principal) {
	t.Helper()

	require.Equal(t, id, p.Obj.Id)

	require.Equal(t, boolAttr, p.Obj.Attr[boolAttrKey].GetBoolValue())
	require.Equal(t, stringAttr, p.Obj.Attr[stringAttrKey].GetStringValue())
	require.Equal(t, doubleAttr, p.Obj.Attr[doubleAttrKey].GetNumberValue())
	for i, val := range listAttr {
		require.Equal(t, val, p.Obj.Attr[listAttrKey].GetListValue().Values[i].GetStringValue())
	}
	for key, val := range mapAttr {
		require.Equal(t, val, p.Obj.Attr[mapAttrKey].GetStructValue().AsMap()[key].(string))
	}

	require.Equal(t, attrValue, p.Obj.Attr[attrKey].GetStringValue())
	require.Equal(t, version, p.Obj.PolicyVersion)
	for i, role := range roles {
		require.Equal(t, role, p.Obj.Roles[i])
	}
	require.Equal(t, scope, p.Obj.Scope)
}

func cmpResource(t *testing.T, r *cerbos.Resource) {
	t.Helper()

	require.Equal(t, id, r.Obj.Id)
	require.Equal(t, kind, r.Obj.Kind)

	require.Equal(t, boolAttr, r.Obj.Attr[boolAttrKey].GetBoolValue())
	require.Equal(t, stringAttr, r.Obj.Attr[stringAttrKey].GetStringValue())
	require.Equal(t, doubleAttr, r.Obj.Attr[doubleAttrKey].GetNumberValue())
	for i, val := range listAttr {
		require.Equal(t, val, r.Obj.Attr[listAttrKey].GetListValue().Values[i].GetStringValue())
	}
	for key, val := range mapAttr {
		require.Equal(t, val, r.Obj.Attr[mapAttrKey].GetStructValue().AsMap()[key].(string))
	}

	require.Equal(t, attrValue, r.Obj.Attr[attrKey].GetStringValue())
	require.Equal(t, version, r.Obj.PolicyVersion)
	require.Equal(t, scope, r.Obj.Scope)
}

func cmpPrincipalPolicy(t *testing.T, pp *cerbos.PrincipalPolicy) {
	t.Helper()

	require.Equal(t, principal, pp.Obj.Principal)
	require.Equal(t, scope, pp.Obj.Scope)
	require.Equal(t, version, pp.Obj.Version)
	require.Equal(t, []string{exportVariablesName}, pp.Obj.Variables.Import)
	require.Equal(t, map[string]string{variableName: variableExpr}, pp.Obj.Variables.Local)
}

func cmpResourcePolicy(t *testing.T, rp *cerbos.ResourcePolicy) {
	t.Helper()

	require.Equal(t, resource, rp.Obj.Resource)
	require.Equal(t, scope, rp.Obj.Scope)
	require.Equal(t, version, rp.Obj.Version)
	require.Equal(t, []string{exportVariablesName}, rp.Obj.Variables.Import)
	require.Equal(t, map[string]string{variableName: variableExpr}, rp.Obj.Variables.Local)
}

func cmpPrincipalRule(t *testing.T, pr *cerbos.PrincipalRule) {
	t.Helper()

	require.Equal(t, resource, pr.Obj.Resource)
	require.Equal(t, actionApprove, pr.Obj.Actions[0].Action)
	require.Equal(t, actionCreate, pr.Obj.Actions[1].Action)
	require.Equal(t, effectv1.Effect_EFFECT_ALLOW, pr.Obj.Actions[0].Effect)
	require.Equal(t, effectv1.Effect_EFFECT_DENY, pr.Obj.Actions[1].Effect)
}

func cmpResourceRule(t *testing.T, rr *cerbos.ResourceRule) {
	t.Helper()

	require.Equal(t, actionApprove, rr.Obj.Actions[0])
	for i, role := range roles {
		require.EqualValues(t, role, rr.Obj.DerivedRoles[i])
	}
	for i, role := range roles {
		require.EqualValues(t, role, rr.Obj.Roles[i])
	}
}

func cmpPolicySet(t *testing.T, ps *cerbos.PolicySet) {
	t.Helper()

	policies := ps.GetPolicies()
	require.Len(t, policies, 4)
	require.IsType(t, &policyv1.Policy_DerivedRoles{}, policies[0].PolicyType)
	require.IsType(t, &policyv1.Policy_ExportVariables{}, policies[1].PolicyType)
	require.IsType(t, &policyv1.Policy_PrincipalPolicy{}, policies[2].PolicyType)
	require.IsType(t, &policyv1.Policy_ResourcePolicy{}, policies[3].PolicyType)
}

func cmpSchema(t *testing.T, s *cerbos.Schema) {
	t.Helper()

	require.Equal(t, ref, s.Obj.Ref)
	require.Equal(t, actionApprove, s.Obj.IgnoreWhen.Actions[0])
}

func newDerivedRoles(t *testing.T) *cerbos.DerivedRoles {
	t.Helper()

	return cerbos.NewDerivedRoles(derivedRolesName).
		WithVariablesImports(exportVariablesName).
		WithVariable(variableName, variableExpr).
		AddRole(roleName, roles)
}

func newExportVariables(t *testing.T) *cerbos.ExportVariables {
	t.Helper()

	return cerbos.NewExportVariables(exportVariablesName).
		AddVariable(variableName, variableExpr)
}

func newPrincipal(t *testing.T) *cerbos.Principal {
	t.Helper()

	return cerbos.NewPrincipal(id, roles[0]).
		WithAttributes(attributes).
		WithAttr(attrKey, attrValue).
		WithPolicyVersion(version).
		WithRoles(roles[1], roles[2]).
		WithScope(scope)
}

func newResource(t *testing.T) *cerbos.Resource {
	t.Helper()

	return cerbos.NewResource(kind, id).
		WithAttributes(attributes).
		WithAttr(attrKey, attrValue).
		WithPolicyVersion(version).
		WithScope(scope)
}

func newPrincipalPolicy(t *testing.T) *cerbos.PrincipalPolicy {
	t.Helper()

	return cerbos.NewPrincipalPolicy(principal, version).
		WithScope(scope).
		WithVariablesImports(exportVariablesName).
		WithVariable(variableName, variableExpr).
		AddPrincipalRules(
			newPrincipalRule(t),
		)
}

func newResourcePolicy(t *testing.T) *cerbos.ResourcePolicy {
	t.Helper()

	return cerbos.NewResourcePolicy(resource, version).
		WithScope(scope).
		WithVariablesImports(exportVariablesName).
		WithVariable(variableName, variableExpr)
}

func newPrincipalRule(t *testing.T) *cerbos.PrincipalRule {
	t.Helper()

	return cerbos.NewPrincipalRule(resource).
		AllowAction(actionApprove).
		DenyAction(actionCreate)
}

func newResourceRule(t *testing.T) *cerbos.ResourceRule {
	t.Helper()

	return cerbos.NewAllowResourceRule(actionApprove).
		WithDerivedRoles(roles...).
		WithName(ruleName).
		WithRoles(roles...)
}

func newPolicySet(t *testing.T) *cerbos.PolicySet {
	t.Helper()

	return cerbos.NewPolicySet().
		AddDerivedRoles(newDerivedRoles(t)).
		AddExportVariables(newExportVariables(t)).
		AddPrincipalPolicies(newPrincipalPolicy(t)).
		AddResourcePolicies(newResourcePolicy(t))
}

func newSchema(t *testing.T) *cerbos.Schema {
	t.Helper()

	return cerbos.NewSchema(ref).
		AddIgnoredActions(actionApprove)
}
