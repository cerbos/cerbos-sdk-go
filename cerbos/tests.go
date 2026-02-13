// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package cerbos

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/internal/tests"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

const timeout = 30 * time.Second

func TestClient[P PrincipalContext, C Client[C, P]](c Client[C, P]) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		token := tests.GenerateToken(t, time.Now().Add(5*time.Minute)) //nolint:mnd
		c := c.With(
			AuxDataJWT(token, ""),
			IncludeMeta(true),
			Headers("wibble", "wobble"),
			AddAnnotations(map[string]*structpb.Value{"cerbos.dev/foo": structpb.NewStringValue("bar")}),
		)

		t.Run("CheckResources", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resources := NewResourceBatch().
				Add(
					NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "defer").
				Add(
					NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "approve").
				Add(
					NewResource("leave_request", "XX225").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "engineering",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "mary",
							"team":       "frontend",
						}), "approve")

			check := func(t *testing.T, have *CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotEmpty(t, have.GetRequestId())

				haveXX125 := have.GetResource("XX125", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.False(t, haveXX125.IsAllowed("approve"))
				require.True(t, haveXX125.IsAllowed("defer"))

				haveXX225 := have.GetResource("XX225")
				require.NoError(t, haveXX225.Err())
				require.False(t, haveXX225.IsAllowed("approve"))
			}

			t.Run("Direct", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)

				require.NotNil(t, have.Results[0].Meta, "no metadata found in the result")
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)

				require.NotNil(t, have.Results[0].Meta, "no metadata found in the result")
			})

			t.Run("TestRequestIDGenerator", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.With(RequestIDGenerator(func(_ context.Context) string {
					return "foo"
				})).CheckResources(ctx, principal, resources)
				require.NoError(t, err)
				require.Equal(t, "foo", have.GetRequestId())
			})
		})

		t.Run("CheckResourcesScoped", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithScope("acme.hr").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
					"ip_address": "10.20.5.5",
				})

			resources := NewResourceBatch().
				Add(
					NewResource("leave_request", "XX125").
						WithScope("acme.hr.uk").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create").
				Add(
					NewResource("leave_request", "XX225").
						WithScope("acme.hr").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create")

			check := func(t *testing.T, have *CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotEmpty(t, have.GetRequestId())

				haveXX125 := have.GetResource("XX125", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.True(t, haveXX125.IsAllowed("delete"))
				require.True(t, haveXX125.IsAllowed("create"))
				require.Equal(t, "acme.hr.uk", haveXX125.Resource.Scope)

				haveXX225 := have.GetResource("XX225", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX225.Err())
				require.True(t, haveXX225.IsAllowed("view:public"))
				require.False(t, haveXX225.IsAllowed("delete"))
				require.True(t, haveXX225.IsAllowed("create"))
				require.Equal(t, "acme.hr", haveXX225.Resource.Scope)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("CheckResourcesOutput", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resources := NewResourceBatch().Add(
				NewResource("equipment_request", "XX125").
					WithScope("acme").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}), "view:public", "approve", "create",
			)

			check := func(t *testing.T, have *CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotEmpty(t, have.GetRequestId())

				haveXX125 := have.GetResource("XX125")
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.False(t, haveXX125.IsAllowed("approve"))
				require.True(t, haveXX125.IsAllowed("create"))
				require.Equal(t, "acme", haveXX125.Resource.Scope)

				wantStruct, err := structpb.NewStruct(map[string]any{
					"id":               "john",
					"keys":             "XX125",
					"formatted_string": "id:john",
					"some_bool":        true,
					"some_list":        []any{"foo", "bar"},
					"something_nested": map[string]any{
						"nested_str":              "foo",
						"nested_bool":             false,
						"nested_list":             []any{"nest_foo", 1.01},
						"nested_formatted_string": "id:john",
					},
				})
				require.NoError(t, err, "Failed to create wanted output")
				wantOutput1 := structpb.NewStructValue(wantStruct)
				haveOutput1 := haveXX125.Output("resource.equipment_request.vdefault#public-view")
				require.Empty(t, cmp.Diff(wantOutput1, haveOutput1, protocmp.Transform()))

				wantOutput2 := structpb.NewStringValue("create_allowed:john")
				haveOutput2 := haveXX125.Output("resource.equipment_request.vdefault/acme#rule-001")
				require.Empty(t, cmp.Diff(wantOutput2, haveOutput2, protocmp.Transform()))
			}

			t.Run("Direct", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("IsAllowed", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resource := NewResource("leave_request", "XX125").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"id":         "XX125",
					"owner":      "john",
					"team":       "design",
				})

			t.Run("Direct", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.IsAllowed(ctx, principal, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := c.WithPrincipal(principal).IsAllowed(ctx, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})
		})

		t.Run("PlanResources", func(t *testing.T) {
			principal := NewPrincipal("maggie").
				WithRoles("manager").
				WithAttr("geography", "US").
				WithAttr("department", "marketing").
				WithAttr("team", "design").
				WithAttr("managed_geographies", "US").
				WithAttr("reader", false)

			resource := NewResource("leave_request", "").
				WithPolicyVersion("20210210").
				WithAttr("geography", "US")

			cc := c.With(IncludeMeta(true))

			check := func(t *testing.T, have *PlanResourcesResponse, err error) {
				t.Helper()
				is := require.New(t)
				require.NotEmpty(t, have.GetRequestId())

				is.NoError(err)
				is.Equal(enginev1.PlanResourcesFilter_KIND_CONDITIONAL, have.Filter.Kind, "Expected conditional filter")
				expression := have.Filter.Condition.GetExpression()
				is.NotNil(expression)
				is.Equal("eq", expression.Operator)
				is.Equal("request.resource.attr.status", expression.Operands[0].GetVariable())
				is.Equal("PENDING_APPROVAL", expression.Operands[1].GetValue().GetStringValue())
				t.Log(have.Meta.FilterDebug)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := cc.PlanResources(ctx, principal, resource, "approve")
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := cc.WithPrincipal(principal).PlanResources(ctx, resource, "approve")
				check(t, have, err)
			})

			t.Run("TestRequestIDGenerator", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := cc.With(RequestIDGenerator(func(_ context.Context) string {
					return "foo"
				})).PlanResources(ctx, principal, resource, "approve")
				require.NoError(t, err)
				require.Equal(t, "foo", have.GetRequestId())
			})

			t.Run("MultipleActions", func(t *testing.T) {
				ctx := timeoutCtx(t)
				have, err := cc.PlanResources(ctx, principal, resource, "approve", "view")
				require.NoError(t, err)
				require.NotEmpty(t, have.GetRequestId())

				require.Equal(t, enginev1.PlanResourcesFilter_KIND_CONDITIONAL, have.Filter.Kind, "Expected conditional filter")
				expression := have.Filter.Condition.GetExpression()
				require.NotNil(t, expression)
				require.Equal(t, "and", expression.Operator)
				require.Equal(t, "eq", expression.GetOperands()[0].GetExpression().GetOperator())
			})
		})

		t.Run("PartialRequests", func(t *testing.T) {
			principal := NewPrincipal("john")
			resource := NewResource("leave_request", "").
				WithPolicyVersion("20210210")

			t.Run("Disabled", func(t *testing.T) {
				ctx := timeoutCtx(t)
				// The returned error wouldn't be a gRPC error because it's intercepted locally.
				_, err := c.CheckResources(ctx, principal, NewResourceBatch().Add(resource, "run"))
				require.Error(t, err)
				require.Equal(t, codes.Unknown, status.Code(err))
			})

			t.Run("Enabled", func(t *testing.T) {
				cc := c.With(AllowPartialRequests(), SetAnnotations(map[string]*structpb.Value{"cerbos.dev/foo": structpb.NewStringValue("bar")}))
				requireGRPCErr := func(t *testing.T, err error) {
					t.Helper()
					require.Error(t, err)
					// The returned error would be a gRPC error because it goes all the way to the server.
					require.Equal(t, codes.InvalidArgument, status.Code(err))
				}

				t.Run("CheckResources", func(t *testing.T) {
					ctx := timeoutCtx(t)
					_, err := cc.CheckResources(ctx, principal, NewResourceBatch().Add(resource, "run"))
					requireGRPCErr(t, err)
				})

				t.Run("IsAllowed", func(t *testing.T) {
					ctx := timeoutCtx(t)
					_, err := cc.IsAllowed(ctx, principal, resource, "run")
					requireGRPCErr(t, err)
				})

				t.Run("PlanResources", func(t *testing.T) {
					ctx := timeoutCtx(t)
					_, err := cc.PlanResources(ctx, principal, resource)
					requireGRPCErr(t, err)
				})
			})
		})
	}
}

func timeoutCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return ctx
}
