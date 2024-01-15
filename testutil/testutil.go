// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	ContainerRepoEnvVar = "CERBOS_TEST_CONTAINER_REPO"
	ContainerTagEnvVar  = "CERBOS_TEST_CONTAINER_TAG"
	DebugEnvVar         = "CERBOS_TEST_DEBUG"

	defaultContainerRepo = "ghcr.io/cerbos/cerbos"
	defaultContainerTag  = "dev"
)

var errNotReady = errors.New("server not ready")

type CerbosServerLauncher struct {
	pool *dockertest.Pool
	repo string
	tag  string
}

type CerbosServerInstance struct {
	resource *dockertest.Resource
	pool     *dockertest.Pool
	Stop     func() error
	Host     string
	GRPCPort string
	HTTPPort string
}

func (csi *CerbosServerInstance) IsHealthy() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	container, err := csi.pool.Client.InspectContainerWithContext(csi.resource.Container.ID, ctx)
	if err != nil {
		return false, fmt.Errorf("failed to inspect container: %w", err)
	}

	if !container.State.Running {
		if !container.State.FinishedAt.IsZero() {
			return false, backoff.Permanent(fmt.Errorf("container state is %s", container.State.StateString()))
		}

		return false, fmt.Errorf("container state is %s", container.State.StateString())
	}

	exitCode, err := csi.resource.Exec([]string{"/cerbos", "healthcheck", "--insecure"}, dockertest.ExecOptions{Env: container.Config.Env})
	if err != nil {
		return false, fmt.Errorf("failed to execute healthcheck command: %w", err)
	}

	return exitCode == 0, nil
}

func (csi *CerbosServerInstance) WaitForReady(ctx context.Context) error {
	return csi.pool.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return backoff.Permanent(err)
		}

		ready, err := csi.IsHealthy()
		if err != nil {
			return err
		}

		if !ready {
			return errNotReady
		}

		return nil
	})
}

func (csi *CerbosServerInstance) GRPCAddr() string {
	return net.JoinHostPort(csi.Host, csi.GRPCPort)
}

func (csi *CerbosServerInstance) HTTPAddr() string {
	return net.JoinHostPort(csi.Host, csi.HTTPPort)
}

type LaunchConf struct {
	ConfFilePath        string
	PolicyDir           string
	PolicyDirMountPoint string
	AdditionalMounts    []string
	Cmd                 []string
	Env                 []string
}

// NewCerbosServerLauncher creates a launcher for Cerbos containers.
// By default it launches ghcr.io/cerbos/cerbos:latest. The image and/or tag can be overridden with environment variables.
// CERBOS_TEST_CONTAINER_REPO overrides the default container image repository.
// CERBOS_TEST_CONTAINER_TAG overrides the default container tag.
// CERBOS_TEST_DEBUG if set to true, configures the launcher to output container logs to stdout and stderr.
func NewCerbosServerLauncher() (*CerbosServerLauncher, error) {
	repo := envOrDefault(ContainerRepoEnvVar, defaultContainerRepo)
	tag := envOrDefault(ContainerTagEnvVar, defaultContainerTag)

	return NewCerbosServerLauncherFromImage(repo, tag)
}

func NewCerbosServerLauncherFromImage(repo, tag string) (*CerbosServerLauncher, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Docker daemon: %w", err)
	}

	return &CerbosServerLauncher{pool: pool, repo: repo, tag: tag}, nil
}

func (csl *CerbosServerLauncher) Launch(conf LaunchConf) (*CerbosServerInstance, error) {
	options := &dockertest.RunOptions{
		Repository: csl.repo,
		Tag:        csl.tag,
		Cmd:        conf.Cmd,
		Env:        append([]string{"CERBOS_NO_TELEMETRY=1"}, conf.Env...),
	}

	if conf.ConfFilePath != "" {
		confDir, err := filepath.Abs(filepath.Dir(conf.ConfFilePath))
		if err != nil {
			return nil, fmt.Errorf("failed to determine absolute path to %q: %w", conf.ConfFilePath, err)
		}
		confFile := filepath.Base(conf.ConfFilePath)
		options.Mounts = append(options.Mounts, fmt.Sprintf("%s:/conf", confDir))
		options.Env = append(options.Env, "CERBOS_CONFIG=/conf/"+confFile)
	}

	if conf.PolicyDir != "" {
		policyMountPoint := conf.PolicyDirMountPoint
		if policyMountPoint == "" {
			policyMountPoint = "/policies"
		}
		options.Mounts = append(options.Mounts, fmt.Sprintf("%s:%s", conf.PolicyDir, policyMountPoint))
	}

	if len(conf.AdditionalMounts) > 0 {
		options.Mounts = append(options.Mounts, conf.AdditionalMounts...)
	}

	resource, err := csl.pool.RunWithOptions(options)
	if err != nil {
		return nil, fmt.Errorf("failed to start Cerbos server: %w", err)
	}

	instance := &CerbosServerInstance{
		resource: resource,
		pool:     csl.pool,
		Stop:     func() error { return csl.pool.Purge(resource) },
		Host:     "localhost",
		GRPCPort: resource.GetPort("3593/tcp"),
		HTTPPort: resource.GetPort("3592/tcp"),
	}

	debug := false
	if debugVal, ok := os.LookupEnv(DebugEnvVar); ok {
		d, err := strconv.ParseBool(debugVal)
		if err == nil {
			debug = d
		}
	}

	if debug {
		ctx, cancelFunc := context.WithCancel(context.Background())
		go func() {
			if err := csl.pool.Client.Logs(docker.LogsOptions{
				Context:      ctx,
				Container:    resource.Container.ID,
				OutputStream: os.Stdout,
				ErrorStream:  os.Stderr,
				Stdout:       true,
				Stderr:       true,
				Follow:       true,
			}); err != nil {
				cancelFunc()
			}
		}()

		instance.Stop = func() error {
			cancelFunc()
			return csl.pool.Purge(resource)
		}
	}

	return instance, nil
}

func envOrDefault(envVarName, defaultVal string) string {
	val := os.Getenv(envVarName)
	if val == "" {
		return defaultVal
	}

	return val
}

// LaunchCerbosServer is a utility method to start a Cerbos server and wait for it be ready.
func LaunchCerbosServer(ctx context.Context, launchConf LaunchConf) (*CerbosServerInstance, error) {
	launcher, err := NewCerbosServerLauncher()
	if err != nil {
		return nil, fmt.Errorf("failed to create launcher: %w", err)
	}

	server, err := launcher.Launch(launchConf)
	if err != nil {
		return nil, fmt.Errorf("failed to launch server: %w", err)
	}

	return server, server.WaitForReady(ctx)
}
