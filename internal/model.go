// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"

type ReqOpt struct {
	AuxData     *requestv1.AuxData
	IncludeMeta bool
}
