// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package cerbos_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal/tests"
	"github.com/cerbos/cerbos-sdk-go/testutil"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"
)

func TestAdminClient(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confFile := filepath.Join(tests.PathToTestDataDir(t, "configs"), "tcp_with_tls.yaml")
	policyDir := tests.PathToTestDataDir(t, "policies")

	s, err := launcher.Launch(testutil.LaunchConf{
		ConfFilePath: confFile,
		AdditionalMounts: []string{
			fmt.Sprintf("%s:/certs", certsDir),
		},
		Cmd: []string{
			"server",
			"--set=storage.driver=sqlite3",
			"--set=storage.sqlite3.dsn=file::memory:?cache=shared",
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	require.NoError(t, s.WaitForReady(ctx), "Server failed to start")

	ac, err := cerbos.NewAdminClientWithCredentials("passthrough:///"+s.GRPCAddr(), adminUsername, adminPassword, cerbos.WithTLSInsecure(), cerbos.WithConnectTimeout(connectTimeout))
	require.NoError(t, err)

	policies := map[string]string{
		"derived_roles.apatr_common_roles":           "derived_roles/common_roles.yaml",
		"derived_roles.alpha":                        "derived_roles/derived_roles_01.yaml",
		"derived_roles.beta":                         "derived_roles/derived_roles_02.yaml",
		"export_constants.bazqux":                    "export_constants/export_constants_01.yaml",
		"export_variables.foobar":                    "export_variables/export_variables_01.yaml",
		"principal.donald_duck.vdefault":             "principal_policies/policy_02.yaml",
		"principal.donald_duck.vdefault/acme":        "principal_policies/policy_02_acme.yaml",
		"principal.donald_duck.vdefault/acme.hr":     "principal_policies/policy_02_acme.hr.yaml",
		"resource.leave_request.v20210210":           "resource_policies/policy_01.yaml",
		"resource.leave_request.vdefault":            "resource_policies/policy_05.yaml",
		"resource.leave_request.vdefault/acme":       "resource_policies/policy_05_acme.yaml",
		"resource.leave_request.vdefault/acme.hr":    "resource_policies/policy_05_acme.hr.yaml",
		"resource.leave_request.vdefault/acme.hr.uk": "resource_policies/policy_05_acme.hr.uk.yaml",
	}

	schemas := map[string]string{
		"principal.json":                "_schemas/principal.json",
		"resources/leave_request.json":  "_schemas/resources/leave_request.json",
		"resources/purchase_order.json": "_schemas/resources/purchase_order.json",
	}

	t.Run("AddOrUpdatePolicy", func(t *testing.T) {
		ps := cerbos.NewPolicySet()
		for _, p := range policies {
			_, err := ps.AddPolicyFromFileWithErr(filepath.Join(policyDir, p))
			require.NoError(t, err, "Failed to add %s", p)
		}

		err := ac.AddOrUpdatePolicy(context.Background(), ps)
		require.NoError(t, err, "Failed to add or update policies")
	})

	t.Run("ListPolicies", func(t *testing.T) {
		testCases := []struct {
			name    string
			options []cerbos.FilterOption
			want    map[string]string
		}{
			{
				name: "NoFilter",
				want: policies,
			},
			{
				name:    "NameRegexp",
				options: []cerbos.FilterOption{cerbos.WithNameRegexp("leave_req")},
				want: map[string]string{
					"resource.leave_request.v20210210":           "",
					"resource.leave_request.vdefault":            "",
					"resource.leave_request.vdefault/acme":       "",
					"resource.leave_request.vdefault/acme.hr":    "",
					"resource.leave_request.vdefault/acme.hr.uk": "",
				},
			},
			{
				name:    "ScopeRegexp",
				options: []cerbos.FilterOption{cerbos.WithScopeRegexp("acme")},
				want: map[string]string{
					"principal.donald_duck.vdefault/acme":        "",
					"principal.donald_duck.vdefault/acme.hr":     "",
					"resource.leave_request.vdefault/acme":       "",
					"resource.leave_request.vdefault/acme.hr":    "",
					"resource.leave_request.vdefault/acme.hr.uk": "",
				},
			},
			{
				name:    "VersionRegexp",
				options: []cerbos.FilterOption{cerbos.WithVersionRegexp(`\d+`)},
				want: map[string]string{
					"resource.leave_request.v20210210": "",
				},
			},
			{
				name:    "AllRegexp",
				options: []cerbos.FilterOption{cerbos.WithNameRegexp(`.*`), cerbos.WithScopeRegexp(`.*`), cerbos.WithVersionRegexp("def")},
				want: map[string]string{
					"principal.donald_duck.vdefault":             "",
					"principal.donald_duck.vdefault/acme":        "",
					"principal.donald_duck.vdefault/acme.hr":     "",
					"resource.leave_request.vdefault":            "",
					"resource.leave_request.vdefault/acme":       "",
					"resource.leave_request.vdefault/acme.hr":    "",
					"resource.leave_request.vdefault/acme.hr.uk": "",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				have, err := ac.ListPolicies(context.Background(), tc.options...)
				require.NoError(t, err)
				require.Len(t, have, len(tc.want))
				for _, hp := range have {
					require.Contains(t, tc.want, hp, "Policy %s does not exist in list", hp)
				}
			})
		}
	})

	t.Run("InspectPolicies", func(t *testing.T) {
		testCases := []struct {
			name    string
			options []cerbos.FilterOption
			want    map[string][]string
		}{
			{
				name: "NoFilter",
				want: map[string][]string{
					"principal.donald_duck.vdefault":             {"*"},
					"principal.donald_duck.vdefault/acme":        {"*"},
					"principal.donald_duck.vdefault/acme.hr":     {"view:*"},
					"resource.leave_request.v20210210":           {"*", "approve", "create", "defer", "delete", "remind", "view", "view:*", "view:public"},
					"resource.leave_request.vdefault":            {"*"},
					"resource.leave_request.vdefault/acme":       {"create", "view:public"},
					"resource.leave_request.vdefault/acme.hr":    {"approve", "defer", "delete", "view:*"},
					"resource.leave_request.vdefault/acme.hr.uk": {"defer", "delete"},
				},
			},
			{
				name:    "NameRegexp",
				options: []cerbos.FilterOption{cerbos.WithNameRegexp("leave_req")},
				want: map[string][]string{
					"resource.leave_request.v20210210":           {"*", "approve", "create", "defer", "delete", "remind", "view", "view:*", "view:public"},
					"resource.leave_request.vdefault":            {"*"},
					"resource.leave_request.vdefault/acme":       {"create", "view:public"},
					"resource.leave_request.vdefault/acme.hr":    {"approve", "defer", "delete", "view:*"},
					"resource.leave_request.vdefault/acme.hr.uk": {"defer", "delete"},
				},
			},
			{
				name:    "ScopeRegexp",
				options: []cerbos.FilterOption{cerbos.WithScopeRegexp("acme")},
				want: map[string][]string{
					"principal.donald_duck.vdefault/acme":        {"*"},
					"principal.donald_duck.vdefault/acme.hr":     {"view:*"},
					"resource.leave_request.vdefault/acme":       {"create", "view:public"},
					"resource.leave_request.vdefault/acme.hr":    {"approve", "defer", "delete", "view:*"},
					"resource.leave_request.vdefault/acme.hr.uk": {"defer", "delete"},
				},
			},
			{
				name:    "VersionRegexp",
				options: []cerbos.FilterOption{cerbos.WithVersionRegexp(`\d+`)},
				want: map[string][]string{
					"resource.leave_request.v20210210": {"*", "approve", "create", "defer", "delete", "remind", "view", "view:*", "view:public"},
				},
			},
			{
				name:    "AllRegexp",
				options: []cerbos.FilterOption{cerbos.WithNameRegexp(`.*`), cerbos.WithScopeRegexp(`.*`), cerbos.WithVersionRegexp("def")},
				want: map[string][]string{
					"principal.donald_duck.vdefault":             {"*"},
					"principal.donald_duck.vdefault/acme":        {"*"},
					"principal.donald_duck.vdefault/acme.hr":     {"view:*"},
					"resource.leave_request.vdefault":            {"*"},
					"resource.leave_request.vdefault/acme":       {"create", "view:public"},
					"resource.leave_request.vdefault/acme.hr":    {"approve", "defer", "delete", "view:*"},
					"resource.leave_request.vdefault/acme.hr.uk": {"defer", "delete"},
				},
			},
			{
				name: "PolicyIDs",
				options: []cerbos.FilterOption{
					cerbos.WithPolicyID("resource.leave_request.v20210210"),
				},
				want: map[string][]string{
					"resource.leave_request.v20210210": {"*", "approve", "create", "defer", "delete", "remind", "view", "view:*", "view:public"},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				have, err := ac.InspectPolicies(context.Background(), tc.options...)
				require.NoError(t, err)
				require.NotNil(t, have)
				require.NotNil(t, have.Results)
				for fqn, actions := range tc.want {
					t.Run(fqn, func(t *testing.T) {
						require.NotNil(t, have.Results[fqn])
						require.Len(t, have.Results[fqn].Actions, len(actions))
						require.ElementsMatch(t, have.Results[fqn].Actions, actions)
					})
				}
			})
		}
	})

	t.Run("AddOrUpdateSchema", func(t *testing.T) {
		ss := cerbos.NewSchemaSet()
		for k, s := range schemas {
			_, err := ss.AddSchemaFromFileWithIDAndErr(filepath.Join(policyDir, s), k)
			require.NoError(t, err, "Failed to add %s", s)
		}

		err := ac.AddOrUpdateSchema(context.Background(), ss)
		require.NoError(t, err, "Failed to add or update schemas")
	})

	t.Run("ListSchemas", func(t *testing.T) {
		have, err := ac.ListSchemas(context.Background())
		require.NoError(t, err)
		require.Len(t, have, len(schemas))
		for _, hs := range have {
			require.Contains(t, schemas, hs, "Schema %s does not exist in list", hs)
		}
	})
}
