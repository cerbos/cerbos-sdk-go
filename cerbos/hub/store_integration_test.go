// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package hub_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
)

type TestCase[REQ proto.Message, RESP proto.Message] struct {
	Name          string `yaml:"name"`
	Request       REQ    `yaml:"request"`
	WantResponse  RESP   `yaml:"wantResponse"`
	WantError     bool   `yaml:"wantError"`
	WantErrorCode int    `yaml:"wantErrorCode"`
}

func TestStoreClient(t *testing.T) {
	client, storeID := setup(t)

	t.Run("ReplaceFiles", testReplaceFiles(client, storeID))
	t.Run("ModifyFiles", testModifyFiles(client, storeID))
}

func setup(t *testing.T) (*hub.StoreClient, string) {
	t.Helper()

	apiEndpoint := os.Getenv("CERBOS_HUB_API_ENDPOINT")
	if apiEndpoint == "" {
		t.Skipf("Skipping test because Cerbos Hub endpoint is not set")
	}

	storeID := os.Getenv("CERBOS_HUB_STORE_ID")
	if storeID == "" {
		t.Skipf("Skipping test because Cerbos Hub store ID is not set")
	}

	client, err := cerbos.NewHubClient(cerbos.WithHubAPIEndpoint(apiEndpoint))
	require.NoError(t, err, "Failed to create Hub client")

	return client.StoreClient(), storeID
}

func testReplaceFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			zippedData, err := hub.Zip(os.DirFS(filepath.Join("testdata", "modify_files")))
			require.NoError(t, err)

			req := hub.NewReplaceFilesRequest(storeID, "Replace", zippedData)
			haveResp, err := client.ReplaceFilesLenient(context.Background(), req)
			require.NoError(t, err)
			if haveResp != nil {
				require.True(t, haveResp.GetNewStoreVersion() > 0)
			}
		})
	}
}

func testModifyFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			req := hub.NewModifyFilesRequest(storeID, "Test modification")
			addFilesToModifyRequest(t, filepath.Join("testdata", "modify_files", "success"), req)
			haveResp, err := client.ModifyFilesLenient(context.Background(), req)
			require.NoError(t, err)
			if haveResp != nil {
				require.True(t, haveResp.GetNewStoreVersion() > 0)
			}
		})
	}
}

func addFilesToModifyRequest(t *testing.T, path string, req *hub.ModifyFilesRequest) {
	t.Helper()

	fsys := os.DirFS(path)
	require.NoError(t, fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		contents, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		req.AddOrUpdateFile(path, contents)
		return nil
	}))
}
