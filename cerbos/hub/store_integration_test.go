// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package hub_test

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cloud-api/base"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/cerbos/cloud-api/store"
)

var wantFilesList = []string{
	"_schemas/principal.json",
	"_schemas/resources/leave_request.json",
	"_schemas/resources/purchase_order.json",
	"_schemas/resources/salary_record.json",
	"derived_roles/common_roles.yaml",
	"derived_roles/derived_roles_01.yaml",
	"derived_roles/derived_roles_02.yaml",
	"derived_roles/derived_roles_03.yaml",
	"derived_roles/derived_roles_04.yaml",
	"derived_roles/derived_roles_05.yaml",
	"export_constants/export_constants_01.yaml",
	"export_variables/export_variables_01.yaml",
	"principal_policies/policy_01.yaml",
	"principal_policies/policy_02.yaml",
	"principal_policies/policy_02_acme.hr.yaml",
	"principal_policies/policy_02_acme.sales.yaml",
	"principal_policies/policy_02_acme.yaml",
	"principal_policies/policy_03.yaml",
	"principal_policies/policy_04.yaml",
	"principal_policies/policy_05.yaml",
	"principal_policies/policy_06.yaml",
	"resource_policies/disabled_policy_01.yaml",
	"resource_policies/policy_01.yaml",
	"resource_policies/policy_02.yaml",
	"resource_policies/policy_03.yaml",
	"resource_policies/policy_04.yaml",
	"resource_policies/policy_04_test.yaml",
	"resource_policies/policy_05.yaml",
	"resource_policies/policy_05_acme.hr.uk.brighton.kemptown.yaml",
	"resource_policies/policy_05_acme.hr.uk.brighton.yaml",
	"resource_policies/policy_05_acme.hr.uk.london.yaml",
	"resource_policies/policy_05_acme.hr.uk.yaml",
	"resource_policies/policy_05_acme.hr.yaml",
	"resource_policies/policy_05_acme.yaml",
	"resource_policies/policy_06.yaml",
	"resource_policies/policy_07.yaml",
	"resource_policies/policy_07_acme.yaml",
	"resource_policies/policy_08.yaml",
	"resource_policies/policy_09.yaml",
	"resource_policies/policy_10.yaml",
	"resource_policies/policy_11.yaml",
	"resource_policies/policy_12.yaml",
	"resource_policies/policy_13.yaml",
	"resource_policies/policy_14.yaml",
	"resource_policies/policy_15.yaml",
	"resource_policies/policy_16.yaml",
	"resource_policies/policy_17.acme.sales.yaml",
	"resource_policies/policy_17.acme.yaml",
	"resource_policies/policy_17.yaml",
	"resource_policies/policy_18.yaml",
	"role_policies/policy_01_acme.hr.uk.brighton.yaml",
	"role_policies/policy_02_acme.hr.uk.brighton.yaml",
	"role_policies/policy_03_acme.hr.uk.yaml",
	"role_policies/policy_04_acme.hr.uk.yaml",
	"role_policies/policy_05_acme.hr.uk.london.yaml",
	"role_policies/policy_06_acme.hr.uk.brighton.kemptown.yaml",
	"tests/policy_04_test.yaml",
	"tests/policy_05_test.yaml",
}

func TestStoreClientIntegration(t *testing.T) {
	client, storeID := setup(t)

	t.Run("ReplaceFiles", testReplaceFiles(client, storeID))
	t.Run("ModifyFiles", testModifyFiles(client, storeID))
	t.Run("ListFiles", testListFiles(client, storeID))
	t.Run("GetCurrentVersion", testGetCurrentVersion(client, storeID))
	t.Run("GetFiles", testGetFiles(client, storeID))
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
	storeClient := client.StoreClient()

	return storeClient, storeID
}

func resetStore(t *testing.T, storeID string, storeClient *hub.StoreClient) {
	t.Helper()

	zippedData, err := hub.Zip(os.DirFS(filepath.Join("testdata", "replace_files", "success")))
	require.NoError(t, err)

	req := hub.NewReplaceFilesRequest(storeID, "Replace").WithZippedContents(zippedData)
	haveResp, err := storeClient.ReplaceFilesLenient(context.Background(), req)
	require.NoError(t, err)
	require.True(t, haveResp.GetNewStoreVersion() > 0)

	haveFilesList, err := storeClient.ListFiles(context.Background(), hub.NewListFilesRequest(storeID))
	require.NoError(t, err)
	require.ElementsMatch(t, wantFilesList, haveFilesList.GetFiles())
}

func testReplaceFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		resetStore(t, storeID, client)

		testCases := []string{"Zipped", "Unzipped"}
		for _, kind := range testCases {
			t.Run(kind, func(t *testing.T) {
				t.Run("OperationDiscarded", func(t *testing.T) {
					base.ResetCircuitBreaker()
					req := hub.NewReplaceFilesRequest(storeID, "Replace")
					fsys := os.DirFS(filepath.Join("testdata", "replace_files", "success"))
					if kind == "Zipped" {
						zippedData, err := hub.Zip(fsys)
						require.NoError(t, err)
						req = req.WithZippedContents(zippedData)
					} else {
						req = req.WithFiles(listFiles(t, fsys)...)
					}

					_, err := client.ReplaceFiles(context.Background(), req)
					require.Error(t, err)
					t.Log(err)
					haveErr := new(hub.StoreRPCError)
					require.ErrorAs(t, err, haveErr)
					require.Equal(t, store.RPCErrorOperationDiscarded, haveErr.Kind)
				})

				t.Run("InvalidRequest", func(t *testing.T) {
					base.ResetCircuitBreaker()
					req := hub.NewReplaceFilesRequest(storeID, "Replace")
					if kind == "Zipped" {
						req = req.WithZippedContents([]byte("zip"))
					} else {
						req = req.WithFiles()
					}
					_, err := client.ReplaceFiles(context.Background(), req)
					verr := new(hub.InvalidRequestError)
					require.ErrorAs(t, err, verr)
				})

				t.Run("InvalidFiles", func(t *testing.T) {
					base.ResetCircuitBreaker()
					req := hub.NewReplaceFilesRequest(storeID, "Replace")
					fsys := os.DirFS(filepath.Join("testdata", "replace_files", "invalid"))
					if kind == "Zipped" {
						zippedData, err := hub.Zip(fsys)
						require.NoError(t, err)
						req = req.WithZippedContents(zippedData)
					} else {
						req = req.WithFiles(listFiles(t, fsys)...)
					}

					_, err := client.ReplaceFiles(context.Background(), req)
					haveErr := new(hub.StoreRPCError)
					require.ErrorAs(t, err, haveErr)
					require.Equal(t, store.RPCErrorValidationFailure, haveErr.Kind)
					require.Len(t, haveErr.ValidationErrors, 1)

					haveFilesList, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(storeID))
					require.NoError(t, err)
					require.ElementsMatch(t, wantFilesList, haveFilesList.GetFiles())
				})

				t.Run("UnusableFiles", func(t *testing.T) {
					base.ResetCircuitBreaker()
					fsys := os.DirFS(filepath.Join("testdata", "replace_files", "unusable"))
					req := hub.NewReplaceFilesRequest(storeID, "Replace")
					if kind == "Zipped" {
						zippedData, err := hub.Zip(fsys)
						require.NoError(t, err)
						req = req.WithZippedContents(zippedData)
					} else {
						req = req.WithFiles(listFiles(t, fsys)...)
					}

					_, err := client.ReplaceFilesLenient(context.Background(), req)
					haveErr := new(hub.StoreRPCError)
					require.ErrorAs(t, err, haveErr)
					require.Equal(t, store.RPCErrorNoUsableFiles, haveErr.Kind)
					require.ElementsMatch(t, []string{".hidden.yaml", "README.md"}, haveErr.IgnoredFiles)

					haveFilesList, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(storeID))
					require.NoError(t, err)
					require.ElementsMatch(t, wantFilesList, haveFilesList.GetFiles())
				})

				t.Run("UnsuccessfulCondition", func(t *testing.T) {
					base.ResetCircuitBreaker()
					fsys := os.DirFS(filepath.Join("testdata", "replace_files", "conditional"))
					req := hub.NewReplaceFilesRequest(storeID, "Replace")
					if kind == "Zipped" {
						zippedData, err := hub.Zip(fsys)
						require.NoError(t, err)
						req = req.WithZippedContents(zippedData)
					} else {
						req = req.WithFiles(listFiles(t, fsys)...)
					}

					req = req.OnlyIfVersionEquals(math.MaxInt64)
					_, err := client.ReplaceFiles(context.Background(), req)
					haveErr := new(hub.StoreRPCError)
					require.ErrorAs(t, err, haveErr)
					require.Equal(t, store.RPCErrorConditionUnsatisfied, haveErr.Kind)

					haveFilesList, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(storeID))
					require.NoError(t, err)
					require.ElementsMatch(t, wantFilesList, haveFilesList.GetFiles())
				})
			})
		}
	}
}

func listFiles(t *testing.T, fsys fs.FS) []*storev1.File {
	t.Helper()
	out := make([]*storev1.File, 0, 32)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if len(path) > 1 && strings.HasPrefix(filepath.Base(path), ".") {
				return fs.SkipDir
			}
			return nil
		}

		contents, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		if len(contents) == 0 {
			return nil
		}

		out = append(out, &storev1.File{
			Path:     path,
			Contents: contents,
		})

		return nil
	})
	require.NoError(t, err)

	return out
}

func testModifyFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		resetStore(t, storeID, client)

		t.Run("Success", func(t *testing.T) {
			req := hub.NewModifyFilesRequest(storeID, "Test modification")
			addFilesToModifyRequest(t, filepath.Join("testdata", "modify_files", "success"), req)
			haveResp, err := client.ModifyFiles(context.Background(), req)
			require.NoError(t, err)
			require.True(t, haveResp.GetNewStoreVersion() > 0)

			haveGetFiles, err := client.GetFiles(context.Background(), hub.NewGetFilesRequest(storeID, []string{"example.yaml"}))
			require.NoError(t, err)
			want, err := os.ReadFile(filepath.Join("testdata", "modify_files", "success", "example.yaml"))
			require.NoError(t, err)
			have := haveGetFiles.AsMap()
			require.Len(t, have, 1)
			require.Equal(t, want, have["example.yaml"])
		})

		t.Run("InvalidRequest", func(t *testing.T) {
			base.ResetCircuitBreaker()
			req := hub.NewModifyFilesRequest(storeID, "Test modification")
			_, err := client.ModifyFiles(context.Background(), req)
			verr := new(hub.InvalidRequestError)
			require.ErrorAs(t, err, verr)
		})

		t.Run("InvalidFiles", func(t *testing.T) {
			base.ResetCircuitBreaker()
			req := hub.NewModifyFilesRequest(storeID, "Test modification")
			addFilesToModifyRequest(t, filepath.Join("testdata", "modify_files", "invalid"), req)
			_, err := client.ModifyFiles(context.Background(), req)
			haveErr := new(hub.StoreRPCError)
			require.ErrorAs(t, err, haveErr)
			require.Equal(t, store.RPCErrorValidationFailure, haveErr.Kind)
			require.Len(t, haveErr.ValidationErrors, 1)
		})

		t.Run("UnsuccessfulCondition", func(t *testing.T) {
			base.ResetCircuitBreaker()
			req := hub.NewModifyFilesRequest(storeID, "Test modification").OnlyIfVersionEquals(math.MaxInt64)
			addFilesToModifyRequest(t, filepath.Join("testdata", "modify_files", "conditional"), req)
			_, err := client.ModifyFiles(context.Background(), req)
			haveErr := new(hub.StoreRPCError)
			require.ErrorAs(t, err, haveErr)
			require.Equal(t, store.RPCErrorConditionUnsatisfied, haveErr.Kind)
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

func testListFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		resetStore(t, storeID, client)

		t.Run("WithFilterMatch", func(t *testing.T) {
			haveResp, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(storeID).WithFileFilter(hub.FilterPathContains("export_")))
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"export_constants/export_constants_01.yaml", "export_variables/export_variables_01.yaml"}, haveResp.GetFiles())
		})

		t.Run("WithNoFilterMatch", func(t *testing.T) {
			haveResp, err := client.ListFiles(context.Background(), hub.NewListFilesRequest(storeID).WithFileFilter(hub.FilterPathContains("wibble")))
			require.NoError(t, err)
			require.Len(t, haveResp.GetFiles(), 0)
		})
	}
}

func testGetCurrentVersion(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		resetStore(t, storeID, client)

		t.Run("Success", func(t *testing.T) {
			haveResp, err := client.GetCurrentVersion(context.Background(), hub.NewGetCurrentVersionRequest(storeID))
			require.NoError(t, err)
			require.True(t, haveResp.GetStoreVersion() > 0)
			require.Empty(t, cmp.Diff(&storev1.ChangeDetails{
				Description: "Replace",
				Uploader: &storev1.ChangeDetails_Uploader{
					Name: "cerbos-sdk-go",
				},
			}, haveResp.GetChangeDetails(), protocmp.Transform()))
		})
	}
}

func testGetFiles(client *hub.StoreClient, storeID string) func(*testing.T) {
	return func(t *testing.T) {
		resetStore(t, storeID, client)

		t.Run("NonExistent", func(t *testing.T) {
			haveResp, err := client.GetFiles(context.Background(), hub.NewGetFilesRequest(storeID, []string{"wibble.yaml"}))
			require.NoError(t, err)
			require.Len(t, haveResp.GetFiles(), 0)
		})

		t.Run("InvalidRequest", func(t *testing.T) {
			_, err := client.GetFiles(context.Background(), hub.NewGetFilesRequest(storeID, nil))
			verr := new(hub.InvalidRequestError)
			require.ErrorAs(t, err, verr)
		})
	}
}
