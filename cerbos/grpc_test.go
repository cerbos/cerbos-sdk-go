// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package cerbos_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal/tests"
	"github.com/cerbos/cerbos-sdk-go/testutil"
)

const (
	connectTimeout = 1 * time.Second
	readyTimeout   = 5 * time.Second
)

func TestGRPCClient(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")
	withTLSConfFilePath := filepath.Join(confDir, "tcp_with_tls.yaml")

	testCases := []struct {
		name         string
		tls          bool
		confFilePath string
		opts         []cerbos.Opt
	}{
		{
			name:         "with_tls",
			tls:          true,
			confFilePath: withTLSConfFilePath,
			opts:         []cerbos.Opt{cerbos.WithTLSInsecure(), cerbos.WithConnectTimeout(connectTimeout)},
		},
		{
			name:         "without_tls",
			tls:          false,
			confFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
			opts:         []cerbos.Opt{cerbos.WithPlaintext(), cerbos.WithConnectTimeout(connectTimeout)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("tcp", func(t *testing.T) {
				s, err := launcher.Launch(testutil.LaunchConf{
					ConfFilePath: tc.confFilePath,
					PolicyDir:    policyDir,
					AdditionalMounts: []string{
						fmt.Sprintf("%s:/certs", certsDir),
					},
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = s.Stop() })

				ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
				defer cancel()
				require.NoError(t, s.WaitForReady(ctx), "Server failed to start")

				ports := []struct {
					name string
					addr string
				}{
					{
						name: "grpc",
						addr: "passthrough:///" + s.GRPCAddr(),
					},
					{
						name: "http",
						addr: "passthrough:///" + s.HTTPAddr(),
					},
				}
				for _, port := range ports {
					c, err := cerbos.New(port.addr, tc.opts...)
					require.NoError(t, err)

					t.Run(port.name, cerbos.TestClient(c))
				}
			})

			t.Run("uds", func(t *testing.T) {
				if !osSupportsUDS {
					t.Skip("Sharing a Unix domain socket over a Docker bind mount is not supported on this operating system")
				}

				tempDir := t.TempDir()
				s, err := launcher.Launch(testutil.LaunchConf{
					ConfFilePath: tc.confFilePath,
					PolicyDir:    policyDir,
					AdditionalMounts: []string{
						fmt.Sprintf("%s:/certs", certsDir),
						fmt.Sprintf("%s:/sock", tempDir),
					},
					Cmd: []string{
						"server",
						"--set=server.httpListenAddr=unix:/sock/http.sock",
						"--set=server.grpcListenAddr=unix:/sock/grpc.sock",
						"--set=server.udsFileMode=0777",
					},
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = s.Stop() })

				// TODO(cell): The docker health check does not work with UDS
				/*
					ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
					defer cancel()
					require.NoError(t, s.WaitForReady(ctx), "Server failed to start")
				*/

				socketPath := filepath.Join(tempDir, "grpc.sock")
				require.Eventually(t, func() bool {
					_, err := os.Stat(socketPath)
					return err == nil
				}, 1*time.Minute, 100*time.Millisecond)

				addr := fmt.Sprintf("unix://%s", socketPath)
				c, err := cerbos.New(addr, tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", cerbos.TestClient[cerbos.PrincipalCtx, *cerbos.GRPCClient](c))
			})
		})
	}

	t.Run("BatchingAdapter", func(t *testing.T) {
		s, err := launcher.Launch(testutil.LaunchConf{
			ConfFilePath: withTLSConfFilePath,
			PolicyDir:    policyDir,
			AdditionalMounts: []string{
				fmt.Sprintf("%s:/certs", certsDir),
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Stop() })

		ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
		defer cancel()
		require.NoError(t, s.WaitForReady(ctx), "Server failed to start")

		c, err := cerbos.New("passthrough:///"+s.GRPCAddr(), cerbos.WithTLSInsecure(), cerbos.WithConnectTimeout(connectTimeout))
		require.NoError(t, err)

		ba := cerbos.NewBatchingAdapter(c)
		t.Run("StandardTests", cerbos.TestClient(ba))

		t.Run("Batching", func(t *testing.T) {
			cc := ba.WithPrincipal(cerbos.NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				}))

			resources := cerbos.NewResourceBatch()

			for i := range 100 {
				resources.Add(cerbos.NewResource("leave_request", fmt.Sprintf("resource-%d", i)).WithPolicyVersion("20210210").WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"id":         "XX125",
					"owner":      "john",
					"team":       "design",
				}), "approve", "view:public")
			}

			result, err := cc.CheckResources(context.TODO(), resources)
			require.NoError(t, err)
			require.Len(t, result.Results, 100)

			res64 := result.GetResource("resource-64", cerbos.MatchResourcePolicyVersion("20210210"))

			require.False(t, res64.IsAllowed("approve"))
			require.True(t, res64.IsAllowed("view:public"))

			cerbosCallIDs := strings.Split(result.GetCerbosCallId(), "|")
			require.Len(t, cerbosCallIDs, 2)
			require.NotEqual(t, cerbosCallIDs[0], cerbosCallIDs[1])
		})
	})
}
