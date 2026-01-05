// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"iter"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/internal"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

// ToMetadata creates a metadata map suitable for attaching to the uploader and/or internal source fields of the ChangeDetails object.
func ToMetadata(metadata map[string]any) (map[string]*structpb.Value, error) {
	out := make(map[string]*structpb.Value, len(metadata))

	for k, v := range metadata {
		pbVal, err := internal.ToStructPB(v)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata value for '%s': %w", k, err)
		}
		out[k] = pbVal
	}

	return out, nil
}

// Zip creates zipped data from the files in the given file system. To zip a directory, use hub.Zip(os.DirFS(/path/to/dir)).
func Zip(fsys fs.FS) ([]byte, error) {
	buffer := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buffer)
	if err := zipWriter.AddFS(fsys); err != nil {
		return nil, fmt.Errorf("failed to create zip from fs: %w", err)
	}

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip file: %w", err)
	}

	return buffer.Bytes(), nil
}

var errExitWalk = errors.New("exit walk")

// BatchFileOps walks the given file system and produces batches of FileOp objects that can be used with the ModifyFiles RPC.
func BatchFileOps(fsys fs.FS, batchSize int) iter.Seq2[[]*storev1.FileOp, error] {
	return func(yield func([]*storev1.FileOp, error) bool) {
		batch := make([]*storev1.FileOp, 0, batchSize)
		count := 0
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			contents, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}

			batch = append(batch, &storev1.FileOp{
				Op: &storev1.FileOp_AddOrUpdate{
					AddOrUpdate: &storev1.File{
						Path:     path,
						Contents: contents,
					},
				},
			})
			count++

			if count == batchSize {
				if !yield(batch, nil) {
					return errExitWalk
				}

				count = 0
				batch = make([]*storev1.FileOp, 0, batchSize)
			}

			return nil
		})
		if err != nil {
			if errors.Is(err, errExitWalk) {
				return
			}
		}

		yield(batch, err)
	}
}
