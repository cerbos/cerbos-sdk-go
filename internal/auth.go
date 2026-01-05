// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/jdx/go-netrc"
)

const (
	AuthorizationHeader      = "authorization"
	PlaygroundInstanceHeader = "playground-instance"
	UsernameEnvVar           = "CERBOS_USERNAME"
	PasswordEnvVar           = "CERBOS_PASSWORD"
	ServerEnvVar             = "CERBOS_SERVER"
	NetrcFile                = ".netrc"
	NetrcEnvVar              = "NETRC"
	NetrcUserKey             = "login"
	NetrcPassKey             = "password"
)

var (
	errServerNotDefined       = errors.New("server not defined")
	errNoCredentialsFound     = errors.New("no credentials found")
	errNetrcUnsupportedForUDS = errors.New("netrc fallback not supported for Unix domain socket addresses")
)

type Environment interface {
	Getenv(string) string
	LookupEnv(string) (string, bool)
}

type OSEnvironment struct{}

func (OSEnvironment) Getenv(k string) string { return os.Getenv(k) }

func (OSEnvironment) LookupEnv(k string) (string, bool) { return os.LookupEnv(k) }

// LoadBasicAuthData loads basic auth credentials and the server address by considering the following options:
// - User provided values (config or flags)
// - Environment variables
// - netrc file.
func LoadBasicAuthData(env Environment, providedServer, providedUsername, providedPassword string) (server, username, password string, err error) {
	server = coalesceWithEnv(env, providedServer, ServerEnvVar)
	if server == "" {
		return "", "", "", errServerNotDefined
	}

	username = coalesceWithEnv(env, providedUsername, UsernameEnvVar)
	password = coalesceWithEnv(env, providedPassword, PasswordEnvVar)

	if username != "" && password != "" {
		return server, username, password, err
	}

	username, password, err = loadCredsFromNetrc(env, server)
	return server, username, password, err
}

func loadCredsFromNetrc(env Environment, server string) (username, password string, err error) {
	machineName, err := ExtractMachineName(server)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse server target '%s': %w", server, err)
	}

	var netrcPath string
	if np, ok := env.LookupEnv(NetrcEnvVar); ok {
		netrcPath = np
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("failed to determine home directory to load netrc: %w", err)
		}

		netrcPath = filepath.Join(homeDir, NetrcFile)
	}

	n, err := netrc.Parse(netrcPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read netrc from '%s': %w", netrcPath, err)
	}

	m := n.Machine(machineName)
	if m == nil {
		return "", "", errNoCredentialsFound
	}

	username = m.Get(NetrcUserKey)
	password = m.Get(NetrcPassKey)

	if username == "" || password == "" {
		return "", "", errNoCredentialsFound
	}

	return username, password, nil
}

func coalesceWithEnv(env Environment, val, envVar string) string {
	if v := strings.TrimSpace(val); v != "" {
		return v
	}

	if envVal, ok := env.LookupEnv(envVar); ok {
		return envVal
	}

	return val
}

// ExtractMachineName picks out the machine name from a gRPC target.
// See https://github.com/grpc/grpc/blob/master/doc/naming.md
func ExtractMachineName(target string) (string, error) {
	scheme, remainder, ok := strings.Cut(target, ":")
	if !ok {
		return target, nil
	}

	switch strings.ToLower(scheme) {
	case "http", "https":
		u, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("failed to parse address %q: %w", target, err)
		}
		return u.Host, nil
	case "unix", "unix-abstract":
		return "", errNetrcUnsupportedForUDS
	case "dns":
		addr := remainder
		if strings.HasPrefix(addr, "//") {
			_, hostName, ok := strings.Cut(remainder[2:], "/")
			if !ok {
				return "", fmt.Errorf("invalid server target '%s'", target)
			}

			addr = hostName
		}

		m, _, err := net.SplitHostPort(addr)
		return m, err
	}

	m, _, err := net.SplitHostPort(target)
	return m, err
}
