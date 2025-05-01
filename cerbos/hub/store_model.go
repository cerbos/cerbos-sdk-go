// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"github.com/cerbos/cerbos-sdk-go/internal"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type ModifyFilesRequest struct {
	Obj *storev1.ModifyFilesRequest
}

func NewModifyFilesRequest(storeID, message string) *ModifyFilesRequest {
	return &ModifyFilesRequest{
		Obj: &storev1.ModifyFilesRequest{
			StoreId:       storeID,
			ChangeDetails: NewChangeDetails(message).Obj,
		},
	}
}

func (mfr *ModifyFilesRequest) AddOrUpdateFile(path string, contents []byte) *ModifyFilesRequest {
	mfr.Obj.Operations = append(mfr.Obj.Operations, &storev1.FileOp{
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
	mfr.Obj.Operations = append(mfr.Obj.Operations, &storev1.FileOp{
		Op: &storev1.FileOp_Delete{
			Delete: path,
		},
	})

	return mfr
}

func (mfr *ModifyFilesRequest) AddOps(ops ...*storev1.FileOp) *ModifyFilesRequest {
	mfr.Obj.Operations = append(mfr.Obj.Operations, ops...)
	return mfr
}

func (mfr *ModifyFilesRequest) OnlyIfVersionEquals(version int64) *ModifyFilesRequest {
	mfr.Obj.Condition = &storev1.ModifyFilesRequest_Condition{
		StoreVersionMustEqual: version,
	}

	return mfr
}

func (mfr *ModifyFilesRequest) WithChangeDetails(cd *ChangeDetails) *ModifyFilesRequest {
	mfr.Obj.ChangeDetails = cd.Obj
	return mfr
}

func (mfr *ModifyFilesRequest) Proto() *storev1.ModifyFilesRequest {
	return mfr.Obj
}

func (mfr *ModifyFilesRequest) Validate() error {
	return internal.Validate(mfr.Obj)
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
	Obj *storev1.ReplaceFilesRequest
}

func NewReplaceFilesRequest(storeID, message string, zipData []byte) *ReplaceFilesRequest {
	return &ReplaceFilesRequest{
		Obj: &storev1.ReplaceFilesRequest{
			StoreId:        storeID,
			ChangeDetails:  NewChangeDetails(message).Obj,
			ZippedContents: zipData,
		},
	}
}

func (rfr *ReplaceFilesRequest) WithChangeDetails(cd *ChangeDetails) *ReplaceFilesRequest {
	rfr.Obj.ChangeDetails = cd.Obj
	return rfr
}

func (rfr *ReplaceFilesRequest) OnlyIfVersionEquals(version int64) *ReplaceFilesRequest {
	rfr.Obj.Condition = &storev1.ReplaceFilesRequest_Condition{
		StoreVersionMustEqual: version,
	}

	return rfr
}

func (rfr *ReplaceFilesRequest) Proto() *storev1.ReplaceFilesRequest {
	return rfr.Obj
}

func (rfr *ReplaceFilesRequest) Validate() error {
	return internal.Validate(rfr.Obj)
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

type ChangeDetails struct {
	Obj *storev1.ChangeDetails
}

func NewChangeDetails(description string) *ChangeDetails {
	return &ChangeDetails{
		Obj: &storev1.ChangeDetails{
			Description: description,
			Uploader: &storev1.ChangeDetails_Uploader{
				Name: "cerbos-sdk-go",
			},
		},
	}
}

// WithUploader sets the name of the uploader for the store operation.
func (cd *ChangeDetails) WithUploader(name string) *ChangeDetails {
	if cd.Obj.Uploader == nil {
		cd.Obj.Uploader = &storev1.ChangeDetails_Uploader{}
	}

	cd.Obj.Uploader.Name = name
	return cd
}

// WithUploaderDetails sets the complete uploader details object for the store operation.
// Use the `ToMetadata` helper function to construct the metadata object for the uploader.
func (cd *ChangeDetails) WithUploaderDetails(uploader *storev1.ChangeDetails_Uploader) *ChangeDetails {
	cd.Obj.Uploader = uploader
	return cd
}

// WithOriginGit sets the given git repo and hash as the source of the store upload operation.
func (cd *ChangeDetails) WithOriginGit(repo, hash string) *ChangeDetails {
	cd.Obj.Origin = &storev1.ChangeDetails_Git_{
		Git: &storev1.ChangeDetails_Git{
			Repo: repo,
			Hash: hash,
		},
	}

	return cd
}

// WithOriginGitDetails sets the full details about the git commit that is used as the source for this store upload operation.
func (cd *ChangeDetails) WithOriginGitDetails(gitInfo *storev1.ChangeDetails_Git) *ChangeDetails {
	cd.Obj.Origin = &storev1.ChangeDetails_Git_{
		Git: gitInfo,
	}

	return cd
}

// WithOriginInternal sets the source of the store upload operation as an internal, non-git source.
func (cd *ChangeDetails) WithOriginInternal(source string) *ChangeDetails {
	cd.Obj.Origin = &storev1.ChangeDetails_Internal_{
		Internal: &storev1.ChangeDetails_Internal{
			Source: source,
		},
	}

	return cd
}

// WithOriginInternalDetails sets the full details about the internal source used for the store upload operation.
// Use the `ToMetadata` helper function to construct metadata.
func (cd *ChangeDetails) WithOriginInternalDetails(internalInfo *storev1.ChangeDetails_Internal) *ChangeDetails {
	cd.Obj.Origin = &storev1.ChangeDetails_Internal_{
		Internal: internalInfo,
	}

	return cd
}
