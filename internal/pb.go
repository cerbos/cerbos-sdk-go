// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"reflect"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

func ToStructPB(v any) (*structpb.Value, error) {
	val, err := structpb.NewValue(v)
	if err == nil {
		return val, nil
	}

	if t, ok := v.(time.Time); ok {
		return structpb.NewStringValue(t.Format(time.RFC3339)), nil
	}

	vv := reflect.ValueOf(v)
	switch vv.Kind() {
	case reflect.Array, reflect.Slice:
		arr := make([]*structpb.Value, vv.Len())
		for i := 0; i < vv.Len(); i++ {
			el := vv.Index(i)
			arr[i], err = ToStructPB(el.Interface())
			if err != nil {
				return nil, err
			}
		}

		return structpb.NewListValue(&structpb.ListValue{Values: arr}), nil
	case reflect.Map:
		if vv.Type().Key().Kind() == reflect.String {
			m := make(map[string]*structpb.Value)

			iter := vv.MapRange()
			for iter.Next() {
				m[iter.Key().String()], err = ToStructPB(iter.Value().Interface())
				if err != nil {
					return nil, err
				}
			}

			return structpb.NewStructValue(&structpb.Struct{Fields: m}), nil
		}
	default:
		return nil, err
	}

	return nil, err
}
