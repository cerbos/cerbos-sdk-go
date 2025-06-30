// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"github.com/cerbos/cerbos-sdk-go/internal"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type ModifyFilesRequest struct {
	obj *storev1.ModifyFilesRequest
}

func NewModifyFilesRequest(storeID, message string) *ModifyFilesRequest {
	return &ModifyFilesRequest{
		obj: &storev1.ModifyFilesRequest{
			StoreId:       storeID,
			ChangeDetails: NewChangeDetails(message).obj,
		},
	}
}

func (mfr *ModifyFilesRequest) AddOrUpdateFile(path string, contents []byte) *ModifyFilesRequest {
	mfr.obj.Operations = append(mfr.obj.Operations, &storev1.FileOp{
		Op: &storev1.FileOp_AddOrUpdate{
			AddOrUpdate: &storev1.File{
				Path:     path,
				Contents: contents,
			},
		},
	})

	return mfr
}

func (mfr *ModifyFilesRequest) DeleteFile(path string) *ModifyFilesRequest {
	mfr.obj.Operations = append(mfr.obj.Operations, &storev1.FileOp{
		Op: &storev1.FileOp_Delete{
			Delete: path,
		},
	})

	return mfr
}

func (mfr *ModifyFilesRequest) AddOps(ops ...*storev1.FileOp) *ModifyFilesRequest {
	mfr.obj.Operations = append(mfr.obj.Operations, ops...)
	return mfr
}

func (mfr *ModifyFilesRequest) OnlyIfVersionEquals(version int64) *ModifyFilesRequest {
	mfr.obj.Condition = &storev1.ModifyFilesRequest_Condition{
		StoreVersionMustEqual: version,
	}

	return mfr
}

func (mfr *ModifyFilesRequest) WithChangeDetails(cd *ChangeDetails) *ModifyFilesRequest {
	mfr.obj.ChangeDetails = cd.obj
	return mfr
}

func (mfr *ModifyFilesRequest) Proto() *storev1.ModifyFilesRequest {
	return mfr.obj
}

func (mfr *ModifyFilesRequest) Validate() error {
	return internal.Validate(mfr.obj)
}

type ModifyFilesResponse struct {
	*storev1.ModifyFilesResponse
}

func (mfr *ModifyFilesResponse) String() string {
	return protojson.Format(mfr.ModifyFilesResponse)
}

func (mfr *ModifyFilesResponse) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(mfr.ModifyFilesResponse)
}

type ReplaceFilesRequest struct {
	obj *storev1.ReplaceFilesRequest
}

func NewReplaceFilesRequest(storeID, message string) *ReplaceFilesRequest {
	return &ReplaceFilesRequest{
		obj: &storev1.ReplaceFilesRequest{
			StoreId:       storeID,
			ChangeDetails: NewChangeDetails(message).obj,
		},
	}
}

func (rfr *ReplaceFilesRequest) WithFiles(files ...*storev1.File) *ReplaceFilesRequest {
	rfr.obj.Contents = &storev1.ReplaceFilesRequest_Files_{Files: &storev1.ReplaceFilesRequest_Files{Files: files}}
	return rfr
}

func (rfr *ReplaceFilesRequest) WithZippedContents(zippedContents []byte) *ReplaceFilesRequest {
	rfr.obj.Contents = &storev1.ReplaceFilesRequest_ZippedContents{ZippedContents: zippedContents}
	return rfr
}

func (rfr *ReplaceFilesRequest) WithChangeDetails(cd *ChangeDetails) *ReplaceFilesRequest {
	rfr.obj.ChangeDetails = cd.obj
	return rfr
}

func (rfr *ReplaceFilesRequest) OnlyIfVersionEquals(version int64) *ReplaceFilesRequest {
	rfr.obj.Condition = &storev1.ReplaceFilesRequest_Condition{
		StoreVersionMustEqual: version,
	}

	return rfr
}

func (rfr *ReplaceFilesRequest) Proto() *storev1.ReplaceFilesRequest {
	return rfr.obj
}

func (rfr *ReplaceFilesRequest) Validate() error {
	return internal.Validate(rfr.obj)
}

type ReplaceFilesResponse struct {
	*storev1.ReplaceFilesResponse
}

func (rfr *ReplaceFilesResponse) String() string {
	return protojson.Format(rfr.ReplaceFilesResponse)
}

func (rfr *ReplaceFilesResponse) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(rfr.ReplaceFilesResponse)
}

type ListFilesRequest struct {
	obj *storev1.ListFilesRequest
}

func NewListFilesRequest(storeID string) *ListFilesRequest {
	return &ListFilesRequest{
		obj: &storev1.ListFilesRequest{
			StoreId: storeID,
		},
	}
}

func (lfr *ListFilesRequest) WithFileFilter(filter *FileFilter) *ListFilesRequest {
	lfr.obj.Filter = filter.obj
	return lfr
}

func (lfr *ListFilesRequest) Proto() *storev1.ListFilesRequest {
	return lfr.obj
}

func (lfr *ListFilesRequest) Validate() error {
	return internal.Validate(lfr.obj)
}

type ListFilesResponse struct {
	*storev1.ListFilesResponse
}

func (lfr *ListFilesResponse) String() string {
	return protojson.Format(lfr.ListFilesResponse)
}

func (lfr *ListFilesResponse) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(lfr.ListFilesResponse)
}

type FileFilter struct {
	obj *storev1.FileFilter
}

// Create a filter that matches the given path exactly.
func FilterPathEqual(path string) *FileFilter {
	return &FileFilter{
		obj: &storev1.FileFilter{
			Path: &storev1.StringMatch{
				Match: &storev1.StringMatch_Equals{
					Equals: path,
				},
			},
		},
	}
}

// FilterPathIn creates a filter that matches one or more of the set of paths exactly.
func FilterPathIn(paths ...string) *FileFilter {
	return &FileFilter{
		obj: &storev1.FileFilter{
			Path: &storev1.StringMatch{
				Match: &storev1.StringMatch_In{
					In: &storev1.StringMatch_InList{Values: paths},
				},
			},
		},
	}
}

// FilterPathContains creates a filter that partially matches the given path.
func FilterPathContains(path string) *FileFilter {
	return &FileFilter{
		obj: &storev1.FileFilter{
			Path: &storev1.StringMatch{
				Match: &storev1.StringMatch_Contains{
					Contains: path,
				},
			},
		},
	}
}

func (ff *FileFilter) Proto() *storev1.FileFilter {
	return ff.obj
}

func (ff *FileFilter) Validate() error {
	return internal.Validate(ff.obj)
}

type GetFilesRequest struct {
	obj *storev1.GetFilesRequest
}

func NewGetFilesRequest(storeID string, files []string) *GetFilesRequest {
	return &GetFilesRequest{
		obj: &storev1.GetFilesRequest{
			StoreId: storeID,
			Files:   files,
		},
	}
}

func (gfr *GetFilesRequest) Proto() *storev1.GetFilesRequest {
	return gfr.obj
}

func (gfr *GetFilesRequest) Validate() error {
	return internal.Validate(gfr.obj)
}

type GetFilesResponse struct {
	*storev1.GetFilesResponse
}

func (gfr *GetFilesResponse) AsMap() map[string][]byte {
	files := gfr.GetFiles()
	m := make(map[string][]byte, len(files))
	for _, f := range files {
		m[f.GetPath()] = f.GetContents()
	}

	return m
}

func (gfr *GetFilesResponse) String() string {
	return protojson.Format(gfr.GetFilesResponse)
}

func (gfr *GetFilesResponse) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(gfr.GetFilesResponse)
}

type ChangeDetails struct {
	obj *storev1.ChangeDetails
}

func NewChangeDetails(description string) *ChangeDetails {
	return &ChangeDetails{
		obj: &storev1.ChangeDetails{
			Description: description,
			Uploader: &storev1.ChangeDetails_Uploader{
				Name: "cerbos-sdk-go",
			},
		},
	}
}

// WithUploader sets the name of the uploader for the store operation.
func (cd *ChangeDetails) WithUploader(name string) *ChangeDetails {
	if cd.obj.Uploader == nil {
		cd.obj.Uploader = &storev1.ChangeDetails_Uploader{}
	}

	cd.obj.Uploader.Name = name
	return cd
}

// WithUploaderDetails sets the complete uploader details object for the store operation.
// Use the `ToMetadata` helper function to construct the metadata object for the uploader.
func (cd *ChangeDetails) WithUploaderDetails(uploader *storev1.ChangeDetails_Uploader) *ChangeDetails {
	cd.obj.Uploader = uploader
	return cd
}

// WithOriginGit sets the given git repo and hash as the source of the store upload operation.
func (cd *ChangeDetails) WithOriginGit(repo, hash string) *ChangeDetails {
	cd.obj.Origin = &storev1.ChangeDetails_Git_{
		Git: &storev1.ChangeDetails_Git{
			Repo: repo,
			Hash: hash,
		},
	}

	return cd
}

// WithOriginGitDetails sets the full details about the git commit that is used as the source for this store upload operation.
func (cd *ChangeDetails) WithOriginGitDetails(gitInfo *storev1.ChangeDetails_Git) *ChangeDetails {
	cd.obj.Origin = &storev1.ChangeDetails_Git_{
		Git: gitInfo,
	}

	return cd
}

// WithOriginInternal sets the source of the store upload operation as an internal, non-git source.
func (cd *ChangeDetails) WithOriginInternal(source string) *ChangeDetails {
	cd.obj.Origin = &storev1.ChangeDetails_Internal_{
		Internal: &storev1.ChangeDetails_Internal{
			Source: source,
		},
	}

	return cd
}

// WithOriginInternalDetails sets the full details about the internal source used for the store upload operation.
// Use the `ToMetadata` helper function to construct metadata.
func (cd *ChangeDetails) WithOriginInternalDetails(internalInfo *storev1.ChangeDetails_Internal) *ChangeDetails {
	cd.obj.Origin = &storev1.ChangeDetails_Internal_{
		Internal: internalInfo,
	}

	return cd
}
