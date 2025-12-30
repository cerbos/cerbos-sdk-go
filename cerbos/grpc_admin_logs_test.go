// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package cerbos

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"

	connectTimeout = 1 * time.Second
	readyTimeout   = 5 * time.Second
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
		c := &GRPCAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), AuditLogOptions{
			Type: AccessLogs,
			Tail: 10000,
		})

		require.Error(t, err)
	})

	t.Run("should fail if log type is different", func(t *testing.T) {
		c := &GRPCAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AuditLogs(context.Background(), AuditLogOptions{
			Type: AuditLogType(100),
			Tail: 10000,
		})

		require.Error(t, err)
	})
}
