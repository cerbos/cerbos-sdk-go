// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
	"time"
)

type Config struct {
	StatsHandler        stats.Handler
	Address             string
	TLSAuthority        string
	TLSCACert           string
	TLSClientCert       string
	TLSClientKey        string
	UserAgent           string
	PlaygroundInstance  string
	StreamInterceptors  []grpc.StreamClientInterceptor
	UnaryInterceptors   []grpc.UnaryClientInterceptor
	ConnectTimeout      time.Duration
	RetryTimeout        time.Duration
	MaxRetries          uint
	Plaintext           bool
	TLSInsecure         bool
	MaxRecvMsgSizeBytes uint
	MaxSendMsgSizeBytes uint
}
