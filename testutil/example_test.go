// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package testutil_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/testutil"
)

func ExampleLaunchCerbosServer() {
	// Configure Cerbos with the SQLite storage driver
	conf := testutil.LaunchConf{
		Cmd: []string{
			"server",
			"--set=storage.driver=sqlite3",
			"--set=storage.sqlite3.dsn=:mem:?_fk=true",
		},
		Env: []string{
			"CERBOS_LOG_LEVEL=error",
		},
	}

	// Set timeout for launching the server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := testutil.LaunchCerbosServer(ctx, conf)
	if err != nil {
		log.Fatalf("Failed to launch Cerbos server: %v", err)
	}

	defer s.Stop()

	c, err := cerbos.New("passthrough:///"+s.GRPCAddr(), cerbos.WithPlaintext())
	if err != nil {
		log.Fatalf("Failed to create Cerbos client: %v", err)
	}

	allowed, err := c.IsAllowed(context.TODO(),
		cerbos.NewPrincipal("john").
			WithRoles("employee", "manager").
			WithAttr("department", "marketing").
			WithAttr("geography", "GB"),
		cerbos.NewResource("leave_request", "XX125").
			WithAttributes(map[string]any{
				"department": "marketing",
				"geography":  "GB",
				"owner":      "harry",
				"status":     "DRAFT",
			}),
		"view",
	)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	fmt.Println(allowed)
	// Output: false
}
