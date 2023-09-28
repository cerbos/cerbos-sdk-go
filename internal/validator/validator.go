// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

var validator *protovalidate.Validator

func Init() error {
	if validator != nil {
		return nil
	}

	v, err := protovalidate.New(
		protovalidate.WithMessages(
			&policyv1.Policy{},
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create protobuf validator: %w", err)
	}

	validator = v
	return nil
}

func Validate(msg proto.Message) error {
	return validator.Validate(msg)
}
