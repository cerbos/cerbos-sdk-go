// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/stats"

	"github.com/cerbos/cerbos-sdk-go/internal"
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

func NewConfig(address string) *Config {
	return &Config{
		Address:        address,
		ConnectTimeout: 30 * time.Second, //nolint:mnd
		MaxRetries:     3,                //nolint:mnd
		RetryTimeout:   2 * time.Second,  //nolint:mnd
		UserAgent:      internal.UserAgent("grpc"),
	}
}

func MkConn(conf *Config) (*grpc.ClientConn, error) {
	dialOpts, err := mkDialOpts(conf)
	if err != nil {
		return nil, err
	}

	grpcConn, err := grpc.NewClient(conf.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, nil
}

func mkDialOpts(conf *Config) ([]grpc.DialOption, error) {
	dialOpts := []grpc.DialOption{grpc.WithUserAgent(conf.UserAgent)}

	if conf.StatsHandler != nil {
		dialOpts = append(dialOpts, grpc.WithStatsHandler(conf.StatsHandler))
	}

	if conf.ConnectTimeout > 0 {
		dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: conf.ConnectTimeout}))
	}

	streamInterceptors := conf.StreamInterceptors
	unaryInterceptors := conf.UnaryInterceptors

	if conf.MaxRetries > 0 && conf.RetryTimeout > 0 {
		streamInterceptors = append(
			[]grpc.StreamClientInterceptor{
				grpc_retry.StreamClientInterceptor(
					grpc_retry.WithMax(conf.MaxRetries),
					grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
				),
			},
			streamInterceptors...,
		)

		unaryInterceptors = append(
			[]grpc.UnaryClientInterceptor{
				grpc_retry.UnaryClientInterceptor(
					grpc_retry.WithMax(conf.MaxRetries),
					grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
				),
			},
			unaryInterceptors...,
		)
	}

	if len(streamInterceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainStreamInterceptor(streamInterceptors...))
	}

	if len(unaryInterceptors) > 0 {
		dialOpts = append(dialOpts, grpc.WithChainUnaryInterceptor(unaryInterceptors...))
	}

	if conf.Plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConf, err := MkTLSConfig(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		if conf.TLSAuthority != "" {
			dialOpts = append(dialOpts, grpc.WithAuthority(conf.TLSAuthority))
		}
	}

	if conf.PlaygroundInstance != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(newPlaygroundInstanceCredentials(conf.PlaygroundInstance)))
	}

	defaultCallOptions := []grpc.CallOption{grpc.UseCompressor(gzip.Name)}
	if conf.MaxRecvMsgSizeBytes > 0 {
		defaultCallOptions = append(defaultCallOptions, grpc.MaxCallRecvMsgSize(int(conf.MaxRecvMsgSizeBytes))) //nolint:gosec
	}

	if conf.MaxSendMsgSizeBytes > 0 {
		defaultCallOptions = append(defaultCallOptions, grpc.MaxCallSendMsgSize(int(conf.MaxSendMsgSizeBytes))) //nolint:gosec
	}

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(defaultCallOptions...))

	return dialOpts, nil
}

func MkTLSConfig(conf *Config) (*tls.Config, error) {
	tlsConf := internal.DefaultTLSConfig()

	if conf.TLSInsecure {
		tlsConf.InsecureSkipVerify = true
	}

	if conf.TLSCACert != "" {
		bs, err := os.ReadFile(conf.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %s: %w", conf.TLSCACert, err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append CA certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if conf.TLSClientCert != "" && conf.TLSClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(conf.TLSClientCert, conf.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from [%s, %s]: %w", conf.TLSClientCert, conf.TLSClientKey, err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}

func newPlaygroundInstanceCredentials(instance string) playgroundInstanceCredentials {
	return playgroundInstanceCredentials{instance: instance}
}

type playgroundInstanceCredentials struct {
	instance string
}

func (pic playgroundInstanceCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{internal.PlaygroundInstanceHeader: pic.instance}, nil
}

func (playgroundInstanceCredentials) RequireTransportSecurity() bool {
	return false
}
