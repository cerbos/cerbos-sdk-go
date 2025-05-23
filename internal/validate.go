// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"

	"buf.build/go/protovalidate"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func Validate[T proto.Message](obj T) error {
	return protovalidate.Validate(obj)
}

type Validatable interface {
	Err() error
	Validate() error
}

func IsValid[T Validatable](obj T) error {
	if err := obj.Err(); err != nil {
		return err
	}

	return obj.Validate()
}

func ValidatePolicy(p *policyv1.Policy) error {
	if err := Validate(p); err != nil {
		return err
	}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return validateResourcePolicy(pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return validatePrincipalPolicy(pt.PrincipalPolicy)
	case *policyv1.Policy_DerivedRoles:
		return validateDerivedRoles(pt.DerivedRoles)
	case *policyv1.Policy_ExportConstants:
		return validateExportConstants(p)
	case *policyv1.Policy_ExportVariables:
		return validateExportVariables(p)
	default:
		return fmt.Errorf("unknown policy type %T", pt)
	}
}

func validateResourcePolicy(rp *policyv1.ResourcePolicy) (err error) {
	ruleNames := make(map[string]int, len(rp.Rules))
	for i, rule := range rp.Rules {
		ruleName := rule.Name
		if ruleName == "" {
			ruleName = fmt.Sprintf("#%d", i+1)
		}

		// check for rule without any roles or derived roles defined
		if len(rule.Roles) == 0 && len(rule.DerivedRoles) == 0 {
			err = multierr.Append(err, fmt.Errorf("rule %s does not specify any roles or derived roles to match", ruleName))
		}

		// check for name clashes
		if rule.Name == "" {
			continue
		}

		if idx, exists := ruleNames[rule.Name]; exists {
			err = multierr.Append(err, fmt.Errorf("rule #%d has the same name as rule #%d: '%s'", i+1, idx, rule.Name))
		} else {
			ruleNames[rule.Name] = i + 1
		}
	}

	return
}

func validatePrincipalPolicy(rp *policyv1.PrincipalPolicy) (err error) {
	resourceNames := make(map[string]int, len(rp.Rules))
	for i, resourceRules := range rp.Rules {
		if idx, exists := resourceNames[resourceRules.Resource]; exists {
			err = multierr.Append(err,
				fmt.Errorf("duplicate definition of resource '%s' at #%d (previous definition at #%d)", resourceRules.Resource, i+1, idx))
		} else {
			resourceNames[resourceRules.Resource] = i + 1
		}

		ruleNames := make(map[string]int, len(resourceRules.Actions))
		for j, actionRule := range resourceRules.Actions {
			if actionRule.Name == "" {
				continue
			}

			if idx, exists := ruleNames[actionRule.Name]; exists {
				err = multierr.Append(err,
					fmt.Errorf("action rule #%d for resource %s has the same name as action rule #%d: '%s'",
						j+1, resourceRules.Resource, idx, actionRule.Name))
			} else {
				ruleNames[actionRule.Name] = j + 1
			}
		}
	}

	return
}

func validateDerivedRoles(dr *policyv1.DerivedRoles) (err error) {
	roleNames := make(map[string]int, len(dr.Definitions))
	for i, rd := range dr.Definitions {
		// Check for name clashes
		if idx, exists := roleNames[rd.Name]; exists {
			err = multierr.Append(err, fmt.Errorf("derived role definition #%d has the same name as definition #%d: '%s'", i+1, idx, rd.Name))
		} else {
			roleNames[rd.Name] = i + 1
		}

		// Check for rules without any parent roles
		if len(rd.ParentRoles) == 0 {
			err = multierr.Append(err, fmt.Errorf("derived role definition '%s' does not specify any parent roles to match", rd.Name))
		}
	}

	return
}

func validateExportConstants(p *policyv1.Policy) error {
	//nolint:staticcheck
	if len(p.Variables) > 0 {
		return fmt.Errorf("export constants policies do not support the deprecated top-level variables field")
	}

	return nil
}

func validateExportVariables(p *policyv1.Policy) error {
	//nolint:staticcheck
	if len(p.Variables) > 0 {
		return fmt.Errorf("export variables policies do not support the deprecated top-level variables field")
	}

	return nil
}
