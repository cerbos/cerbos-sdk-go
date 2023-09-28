// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"log"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

var Validator *protovalidate.Validator

func init() {
	var err error
	if Validator, err = Init(); err != nil {
		log.Fatal(err.Error())
	}
}

func Init() (*protovalidate.Validator, error) {
	v, err := protovalidate.New(
		protovalidate.WithMessages(
			&policyv1.Policy{},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	return v, nil
}

func Validate(msg proto.Message) error {
	return Validator.Validate(msg)
}
