// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package grpcimpl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/cerbos/cerbos-sdk-go"
	"github.com/cerbos/cerbos-sdk-go/client/testutil"
	auditv1 "github.com/cerbos/cerbos-sdk-go/genpb/cerbos/audit/v1"
	requestv1 "github.com/cerbos/cerbos-sdk-go/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos-sdk-go/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos-sdk-go/genpb/cerbos/svc/v1"
)

func TestCollectLogs(t *testing.T) {
	t.Run("access logs", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			return &responsev1.ListAuditLogEntriesResponse{Entry: &responsev1.ListAuditLogEntriesResponse_AccessLogEntry{
				AccessLogEntry: &auditv1.AccessLogEntry{CallId: "test"},
			}}, nil
		}

		logs, err := collectLogs(receiver)
		require.NoError(t, err)

		log := <-logs
		accessLog, err := log.AccessLog()
		require.NoError(t, err)
		require.Equal(t, "test", accessLog.CallId)
		require.Empty(t, logs)
	})

	t.Run("return io.EOF directly", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			return nil, io.EOF
		}

		logs, err := collectLogs(receiver)
		require.NoError(t, err)
		require.Empty(t, logs)
	})

	t.Run("error from receiver", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) { return nil, errors.New("test-error") }

		logs, err := collectLogs(receiver)
		require.NoError(t, err)

		log := <-logs
		al, err := log.AccessLog()
		require.Nil(t, al)
		require.Error(t, err)
	})
}

func TestAuditLogs(t *testing.T) {
	t.Run("should fail on invalid log options", func(t *testing.T) {
		c := AdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), cerbos.AuditLogOptions{
			Type: cerbos.AccessLogs,
			Tail: 10000,
		})

		require.Error(t, err)
	})

	t.Run("should fail if log type is different", func(t *testing.T) {
		c := AdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), cerbos.AuditLogOptions{
			Type: cerbos.AuditLogType(100),
			Tail: 10000,
		})

		require.Error(t, err)
	})
}

func setUpAdminClientAndPolicySet(t *testing.T) (*AdminClient, *cerbos.PolicySet) {
	t.Helper()

	const (
		adminUsername = "cerbos"
		adminPassword = "cerbosAdmin"
		timeout       = 15 * time.Second
	)

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositorySQLite3(fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))),
		testutil.WithAdminAPI(adminUsername, adminPassword),
	}

	s, err := testutil.StartCerbosServer(serverOpts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Stop()
	})

	ac, err := NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, WithPlaintext(), WithConnectTimeout(timeout))
	require.NoError(t, err)

	ps := cerbos.NewPolicySet()
	err = test.FindPolicyFiles(t, "store", func(path string) error {
		ps.AddPolicyFromFile(path)
		return ps.Err()
	})

	require.NoError(t, err)
	require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))

	return ac, ps
}

func TestListPolicies(t *testing.T) {
	ac, ps := setUpAdminClientAndPolicySet(t)

	t.Run("should get the list of policies", func(t *testing.T) {
		have, err := ac.ListPolicies(context.Background(), cerbos.WithIncludeDisabled())
		require.NoError(t, err)
		require.NotEmpty(t, have)

		policyList := ps.GetPolicies()
		want := make([]string, len(policyList))
		for i, p := range policyList {
			want[i] = namer.PolicyKey(p)
		}
		require.ElementsMatch(t, want, have)
	})

	t.Run("policy metadata should include store identifier", func(t *testing.T) {
		policyList := ps.GetPolicies()
		for _, p := range policyList {
			want := namer.PolicyKey(p)
			t.Run(want, func(t *testing.T) {
				have, err := ac.GetPolicy(context.Background(), want)
				require.NoError(t, err)
				require.Len(t, have, 1)
				require.NotNil(t, have[0].Metadata)
				require.Equal(t, want, have[0].Metadata.StoreIdentifier)
			})
		}
	})
}

func TestFilterPolicies(t *testing.T) {
	ac, ps := setUpAdminClientAndPolicySet(t)

	testFilter := func(t *testing.T, filterOpts ...cerbos.ListPoliciesOption) {
		t.Helper()

		filterOpts = append(filterOpts, cerbos.WithIncludeDisabled())

		have, err := ac.ListPolicies(context.Background(), filterOpts...)
		require.NoError(t, err)
		require.NotEmpty(t, have)

		// Bit of gymnastics to convert the client friendly filterOpts to backend-recognised params
		r := &requestv1.ListPoliciesRequest{}
		for _, opt := range filterOpts {
			opt(r)
		}
		params := storage.ListPolicyIDsParams{
			IncludeDisabled: r.IncludeDisabled,
			NameRegexp:      r.NameRegexp,
			ScopeRegexp:     r.ScopeRegexp,
			VersionRegexp:   r.VersionRegexp,
		}

		policyList := test.FilterPolicies(t, ps.GetPolicies(), params)
		want := make([]string, len(policyList))
		for i, p := range policyList {
			want[i] = namer.PolicyKey(p)
		}
		require.ElementsMatch(t, want, have)
	}

	t.Run("should get the list of filtered policies by name", func(t *testing.T) {
		testFilter(t, cerbos.WithNameRegexp(".*request$"))
	})

	t.Run("should get the list of filtered policies by scope", func(t *testing.T) {
		testFilter(t, cerbos.WithScopeRegexp("acme"))
	})

	t.Run("should get the list of filtered policies by version", func(t *testing.T) {
		testFilter(t, cerbos.WithVersionRegexp("20210210"))
	})

	t.Run("should get the list of filtered policies by all", func(t *testing.T) {
		testFilter(t,
			cerbos.WithNameRegexp(".*(leave|equipment)_[rw]equest$"),
			cerbos.WithScopeRegexp("^acme"),
			cerbos.WithVersionRegexp("default$"),
		)
	})
}
