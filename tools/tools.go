// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build toolsx
// +build toolsx

package tools

import (
	_ "github.com/cerbos/actions/cmd/install-tools"
	_ "golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize"
	_ "gotest.tools/gotestsum"
)
