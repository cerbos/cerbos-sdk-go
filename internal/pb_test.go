// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/cerbos/cerbos-sdk-go/internal"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestToStructPB(t *testing.T) {
	testCases := []struct {
		input      any
		wantOutput *structpb.Value
		wantErr    bool
	}{
		{
			input:      nil,
			wantOutput: structpb.NewNullValue(),
		},
		{
			input:      true,
			wantOutput: structpb.NewBoolValue(true),
		},
		{
			input:      "hello",
			wantOutput: structpb.NewStringValue("hello"),
		},
		{
			input:      42,
			wantOutput: structpb.NewNumberValue(42),
		},
		{
			input:      time.Unix(0, 0).UTC(),
			wantOutput: structpb.NewStringValue("1970-01-01T00:00:00Z"),
		},
		{
			input: []string{"hello", "world"},
			wantOutput: structpb.NewListValue(&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStringValue("hello"),
					structpb.NewStringValue("world"),
				},
			}),
		},
		{
			input: map[string]string{"hello": "world"},
			wantOutput: structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"hello": structpb.NewStringValue("world"),
				},
			}),
		},
		{
			input: map[string][]string{"hello": {"world"}},
			wantOutput: structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"hello": structpb.NewListValue(&structpb.ListValue{
						Values: []*structpb.Value{structpb.NewStringValue("world")},
					}),
				},
			}),
		},
		{
			input: []map[string]string{{"hello": "world"}},
			wantOutput: structpb.NewListValue(&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"hello": structpb.NewStringValue("world"),
						},
					}),
				},
			}),
		},
		{
			input:   struct{}{},
			wantErr: true,
		},
		{
			input:   []any{struct{}{}},
			wantErr: true,
		},
		{
			input:   map[string]any{"wat": struct{}{}},
			wantErr: true,
		},
		{
			input:   map[int]any{42: "hello"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%+v", tc.input), func(t *testing.T) {
			haveOutput, err := internal.ToStructPB(tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.wantOutput, haveOutput, protocmp.Transform()))
			}
		})
	}
}
