// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package authzen_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/authzen"
	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/internal/tests"
	"github.com/cerbos/cerbos-sdk-go/testutil"
)

const (
	requestTimeout = 30 * time.Second
	readyTimeout   = 5 * time.Second
)

func TestAdapter(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	testCases := []struct {
		name         string
		urlSchema    string
		confFilePath string
		httpOpts     []authzen.Opt
		grpcOpts     []cerbos.Opt
	}{
		{
			name:         "with_tls",
			urlSchema:    "https",
			confFilePath: filepath.Join(confDir, "tcp_with_tls.yaml"),
			httpOpts:     []authzen.Opt{authzen.WithTLSInsecure(), authzen.WithTimeout(requestTimeout)},
			grpcOpts:     []cerbos.Opt{cerbos.WithTLSInsecure()},
		},
		{
			name:         "without_tls",
			urlSchema:    "http",
			confFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
			httpOpts:     []authzen.Opt{authzen.WithTimeout(requestTimeout)},
			grpcOpts:     []cerbos.Opt{cerbos.WithPlaintext()},
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

				t.Run("http", func(t *testing.T) {
					httpURL := tc.urlSchema + "://" + s.HTTPAddr()
					c, err := authzen.NewAdapter(httpURL, tc.httpOpts...)
					require.NoError(t, err)

					t.Run("adapter", tests.TestClient[*authzen.PrincipalCtxAdapter, *authzen.Adapter](c))
				})

				t.Run("grpc", func(t *testing.T) {
					c, err := authzen.NewGRPCAdapter(s.GRPCAddr(), tc.grpcOpts...)
					require.NoError(t, err)

					t.Run("adapter", tests.TestClient[*authzen.PrincipalCtxAdapter, *authzen.Adapter](c))
				})
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

				httpSocketPath := filepath.Join(tempDir, "http.sock")
				grpcSocketPath := filepath.Join(tempDir, "grpc.sock")

				require.Eventually(t, func() bool {
					_, err := os.Stat(httpSocketPath)
					return err == nil
				}, 1*time.Minute, 100*time.Millisecond)

				require.Eventually(t, func() bool {
					_, err := os.Stat(grpcSocketPath)
					return err == nil
				}, 1*time.Minute, 100*time.Millisecond)

				t.Run("http", func(t *testing.T) {
					httpURL := tc.urlSchema + "://" + s.HTTPAddr()
					c, err := authzen.NewAdapter(httpURL, authzen.WithUDS(httpSocketPath), authzen.WithTLSInsecure())
					require.NoError(t, err)

					t.Run("adapter", tests.TestClient[*authzen.PrincipalCtxAdapter, *authzen.Adapter](c))
				})

				t.Run("grpc", func(t *testing.T) {
					addr := fmt.Sprintf("unix://%s", grpcSocketPath)
					c, err := authzen.NewGRPCAdapter(addr, tc.grpcOpts...)
					require.NoError(t, err)

					t.Run("adapter", tests.TestClient[*authzen.PrincipalCtxAdapter, *authzen.Adapter](c))
				})
			})
		})
	}
}

func TestGetMetadata(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	s, err := launcher.Launch(testutil.LaunchConf{
		ConfFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
		PolicyDir:    policyDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	require.NoError(t, s.WaitForReady(ctx), "Server failed to start")

	httpURL := "http://" + s.HTTPAddr()
	client, err := authzen.NewClient(httpURL)
	require.NoError(t, err)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metadata, err := client.GetMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	require.Equal(t, httpURL, metadata.GetPolicyDecisionPoint())
	require.Equal(t, httpURL+"/access/v1/evaluation", metadata.GetAccessEvaluationEndpoint())
	require.Equal(t, httpURL+"/access/v1/evaluations", metadata.GetAccessEvaluationsEndpoint())
}

func TestIsAllowed(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	s, err := launcher.Launch(testutil.LaunchConf{
		ConfFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
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

	httpURL := "http://" + s.HTTPAddr()
	client, err := authzen.NewClient(httpURL, authzen.WithTLSInsecure())
	require.NoError(t, err)

	// Generate JWT token for auxData
	token := tests.GenerateToken(t, time.Now().Add(5*time.Minute))

	subjCtx := client.
		With(cerbos.AuxDataJWT(token, "")).
		WithSubject(authzen.NewSubject("user", "john").
			WithCerbosRoles("employee").
			WithCerbosPolicyVersion("20210210").
			WithProperty("department", "marketing").
			WithProperty("geography", "GB").
			WithProperty("team", "design"))

	decision, err := subjCtx.IsAllowed(context.Background(), authzen.NewResource("leave_request", "XX125").
		WithCerbosPolicyVersion("20210210").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("id", "XX125").
		WithProperty("owner", "john").
		WithProperty("team", "design"),
		"defer",
	)
	require.NoError(t, err)
	require.True(t, decision)
}

func TestIsAllowedGRPC(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	testCases := []struct {
		name         string
		confFilePath string
		opts         []cerbos.Opt
	}{
		{
			name:         "with_tls",
			confFilePath: filepath.Join(confDir, "tcp_with_tls.yaml"),
			opts:         []cerbos.Opt{cerbos.WithTLSInsecure()},
		},
		{
			name:         "without_tls",
			confFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
			opts:         []cerbos.Opt{cerbos.WithPlaintext()},
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

				client, err := authzen.NewGRPCClient(s.GRPCAddr(), tc.opts...)
				require.NoError(t, err)

				runIsAllowedGRPCTest(t, client)
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
				client, err := authzen.NewGRPCClient(addr, tc.opts...)
				require.NoError(t, err)

				runIsAllowedGRPCTest(t, client)
			})
		})
	}
}

func runIsAllowedGRPCTest(t *testing.T, client *authzen.Client) {
	t.Helper()

	// Generate JWT token for auxData
	token := tests.GenerateToken(t, time.Now().Add(5*time.Minute))

	subjCtx := client.
		With(cerbos.AuxDataJWT(token, "")).
		WithSubject(authzen.NewSubject("user", "john").
			WithCerbosRoles("employee").
			WithCerbosPolicyVersion("20210210").
			WithProperty("department", "marketing").
			WithProperty("geography", "GB").
			WithProperty("team", "design"))

	decision, err := subjCtx.IsAllowed(context.Background(), authzen.NewResource("leave_request", "XX125").
		WithCerbosPolicyVersion("20210210").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("id", "XX125").
		WithProperty("owner", "john").
		WithProperty("team", "design"),
		"defer",
	)
	require.NoError(t, err)
	require.True(t, decision)
}

func TestAccessEvaluation(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	certsDir := tests.PathToTestDataDir(t, "certs")
	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	s, err := launcher.Launch(testutil.LaunchConf{
		ConfFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
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

	httpURL := "http://" + s.HTTPAddr()
	// httpURL := "http://localhost:3592"
	client, err := authzen.NewClient(httpURL, authzen.WithTLSInsecure())
	require.NoError(t, err)

	// Generate JWT token for auxData
	token := tests.GenerateToken(t, time.Now().Add(5*time.Minute))

	// Create subject (principal)
	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithCerbosPolicyVersion("20210210").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("team", "design")

	// Create batch evaluations - one entry per action
	// Resource XX125: view:public (allow), defer (allow), approve (deny)
	// Resource XX225: approve (deny)
	batch := &authzen.BatchEvaluationRequest{
		DefaultContext: authzen.NewContext().
			WithIncludeMeta(false).
			WithAuxDataMap(map[string]any{
				"jwt": map[string]any{
					"token":    token,
					"keySetId": "",
				},
			}),
		Evaluations: []authzen.BatchEvaluation{
			// XX125 - view:public
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosPolicyVersion("20210210").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("view:public"),
			},
			// XX125 - defer
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosPolicyVersion("20210210").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("defer"),
			},
			// XX125 - approve
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosPolicyVersion("20210210").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("approve"),
			},
			// XX225 - approve
			{
				Resource: authzen.NewResource("leave_request", "XX225").
					WithCerbosPolicyVersion("20210210").
					WithProperty("department", "engineering").
					WithProperty("geography", "GB").
					WithProperty("id", "XX225").
					WithProperty("owner", "mary").
					WithProperty("team", "frontend"),
				Action: authzen.NewAction("approve"),
			},
		},
		DefaultSubject: subject,
		Semantics:      authzen.ExecuteAll,
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.AccessEvaluations(ctx, batch)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 4, result.Count())

	// Verify decisions by index
	// Index 0: XX125 - view:public (should be allowed)
	eval0, err := result.GetEvaluation(0)
	require.NoError(t, err)
	require.True(t, eval0.IsAllowed(), "XX125 view:public should be allowed")

	// Index 1: XX125 - defer (should be allowed)
	eval1, err := result.GetEvaluation(1)
	require.NoError(t, err)
	require.True(t, eval1.IsAllowed(), "XX125 defer should be allowed")

	// Index 2: XX125 - approve (should be denied)
	eval2, err := result.GetEvaluation(2)
	require.NoError(t, err)
	require.False(t, eval2.IsAllowed(), "XX125 approve should be denied")

	// Index 3: XX225 - approve (should be denied)
	eval3, err := result.GetEvaluation(3)
	require.NoError(t, err)
	require.False(t, eval3.IsAllowed(), "XX225 approve should be denied")
}

func TestAccessEvaluationsScoped(t *testing.T) {
	launcher, err := testutil.NewCerbosServerLauncher()
	require.NoError(t, err)

	confDir := tests.PathToTestDataDir(t, "configs")
	policyDir := tests.PathToTestDataDir(t, "policies")

	s, err := launcher.Launch(testutil.LaunchConf{
		ConfFilePath: filepath.Join(confDir, "tcp_without_tls.yaml"),
		PolicyDir:    policyDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	require.NoError(t, s.WaitForReady(ctx), "Server failed to start")

	httpURL := "http://" + s.HTTPAddr()
	client, err := authzen.NewClient(httpURL)
	require.NoError(t, err)

	// Create subject with scope
	subject := authzen.NewSubject("user", "john").
		WithCerbosRoles("employee").
		WithCerbosScope("acme.hr").
		WithProperty("department", "marketing").
		WithProperty("geography", "GB").
		WithProperty("team", "design").
		WithProperty("ip_address", "10.20.5.5")

	// Create batch evaluations - one entry per action
	// Resource XX125 (scope acme.hr.uk): view:public (allow), delete (allow), create (allow)
	// Resource XX225 (scope acme.hr): view:public (allow), delete (deny), create (allow)
	batch := &authzen.BatchEvaluationRequest{
		DefaultContext: authzen.NewContext().WithIncludeMeta(false),
		Evaluations: []authzen.BatchEvaluation{
			// XX125 - view:public
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosScope("acme.hr.uk").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("view:public"),
			},
			// XX125 - delete
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosScope("acme.hr.uk").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("delete"),
			},
			// XX125 - create
			{
				Resource: authzen.NewResource("leave_request", "XX125").
					WithCerbosScope("acme.hr.uk").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX125").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("create"),
			},
			// XX225 - view:public
			{
				Resource: authzen.NewResource("leave_request", "XX225").
					WithCerbosScope("acme.hr").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX225").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("view:public"),
			},
			// XX225 - delete
			{
				Resource: authzen.NewResource("leave_request", "XX225").
					WithCerbosScope("acme.hr").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX225").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("delete"),
			},
			// XX225 - create
			{
				Resource: authzen.NewResource("leave_request", "XX225").
					WithCerbosScope("acme.hr").
					WithProperty("department", "marketing").
					WithProperty("geography", "GB").
					WithProperty("id", "XX225").
					WithProperty("owner", "john").
					WithProperty("team", "design"),
				Action: authzen.NewAction("create"),
			},
		},
		DefaultSubject: subject,
		Semantics:      authzen.ExecuteAll,
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.AccessEvaluations(ctx, batch)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 6, result.Count())

	// Verify decisions by index
	// Index 0: XX125 - view:public (should be allowed)
	eval0, err := result.GetEvaluation(0)
	require.NoError(t, err)
	require.True(t, eval0.IsAllowed(), "XX125 view:public should be allowed")

	// Index 1: XX125 - delete (should be allowed)
	eval1, err := result.GetEvaluation(1)
	require.NoError(t, err)
	require.True(t, eval1.IsAllowed(), "XX125 delete should be allowed")

	// Index 2: XX125 - create (should be allowed)
	eval2, err := result.GetEvaluation(2)
	require.NoError(t, err)
	require.True(t, eval2.IsAllowed(), "XX125 create should be allowed")

	// Index 3: XX225 - view:public (should be allowed)
	eval3, err := result.GetEvaluation(3)
	require.NoError(t, err)
	require.True(t, eval3.IsAllowed(), "XX225 view:public should be allowed")

	// Index 4: XX225 - delete (should be denied)
	eval4, err := result.GetEvaluation(4)
	require.NoError(t, err)
	require.False(t, eval4.IsAllowed(), "XX225 delete should be denied")

	// Index 5: XX225 - create (should be allowed)
	eval5, err := result.GetEvaluation(5)
	require.NoError(t, err)
	require.True(t, eval5.IsAllowed(), "XX225 create should be allowed")
}
