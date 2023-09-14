// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build toolsx
// +build toolsx

package tools

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "gotest.tools/gotestsum"
)
