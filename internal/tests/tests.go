// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func PathToTestDataDir(tb testing.TB, dir string) string {
	tb.Helper()

	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Error("Failed to detect testdata directory")
		return ""
	}

	return filepath.Join(filepath.Dir(currFile), "testdata", dir)
}

func GenerateToken(t *testing.T, expiry time.Time) string {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, "cerbos-test-suite"))
	require.NoError(t, token.Set(jwt.AudienceKey, "cerbos-jwt-tests"))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiry))
	require.NoError(t, token.Set("customString", "foobar"))
	require.NoError(t, token.Set("customInt", 42)) //nolint:gomnd
	require.NoError(t, token.Set("customArray", []string{"A", "B", "C"}))
	require.NoError(t, token.Set("customMap", map[string]any{"A": "AA", "B": "BB", "C": "CC"}))

	keyData, err := os.ReadFile(filepath.Join(PathToTestDataDir(t, "certs"), "signing_key.jwk"))
	require.NoError(t, err)

	keySet, err := jwk.ParseKey(keyData)
	require.NoError(t, err)

	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, keySet))
	require.NoError(t, err)

	return string(tokenBytes)
}
