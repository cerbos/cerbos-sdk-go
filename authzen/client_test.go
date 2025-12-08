// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package cerbos_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

func TestClient(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	testCases := []struct {
		name         string
		tls          bool
		confFilePath string
		opts         []cerbos.Opt
	}{
		{
			name:         "with_tls",
			tls:          true,
			confFilePath: filepath.Join(confDir, "tcp_with_tls.yaml"),
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
					// {
					// 	name: "grpc",
					// 	addr: "passthrough:///" + s.GRPCAddr(),
					// },
					{
						name: "http",
						addr: "passthrough:///" + s.HTTPAddr(),
					},
				}
				for _, port := range ports {
					// TODO: Use AuthZEN adapter
					c, err := cerbos.New(port.addr, tc.opts...)
					require.NoError(t, err)

					// TODO: Use AuthZEN adapter
					t.Run(port.name, tests.TestClient[cerbos.PrincipalCtx, *cerbos.GRPCClient](c))
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

				socketPath := filepath.Join(tempDir, "grpc.sock")
				require.Eventually(t, func() bool {
					_, err := os.Stat(socketPath)
					return err == nil
				}, 1*time.Minute, 100*time.Millisecond)

				addr := fmt.Sprintf("unix://%s", socketPath)
				// TODO: Use AuthZEN adapter
				c, err := cerbos.New(addr, tc.opts...)
				require.NoError(t, err)

				// TODO: Use AuthZEN adapter
				t.Run("grpc", tests.TestClient[cerbos.PrincipalCtx, *cerbos.GRPCClient](c))
			})
		})
	}
}
