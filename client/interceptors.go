// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/bufbuild/connect-go"
)

type userAgentInterceptor struct {
	userAgent string
}

func newUserAgentInterceptor(userAgent string) userAgentInterceptor {
	return userAgentInterceptor{userAgent: userAgent}
}

func (uai userAgentInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("User-Agent", uai.userAgent)
		return next(ctx, req)
	})
}

func (uai userAgentInterceptor) WrapStreamingClient(c connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return uaStreamingClientConn{StreamingClientConn: c(ctx, spec), userAgent: uai.userAgent}
	}
}

func (uai userAgentInterceptor) WrapStreamingHandler(h connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return h
}

type uaStreamingClientConn struct {
	connect.StreamingClientConn
	userAgent string
}

func (uas uaStreamingClientConn) RequestHeader() http.Header {
	h := uas.StreamingClientConn.RequestHeader()
	h.Set("User-Agent", uas.userAgent)
	return h
}

func newPlaygroundInterceptor(instance string) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("playground-instance", instance)
			return next(ctx, req)
		})
	})
}
