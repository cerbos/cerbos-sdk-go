// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"errors"
	"fmt"
	"os"

	localhub "github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/cerbos/cloud-api/hub"
	"github.com/cerbos/cloud-api/store"
	"golang.org/x/oauth2"

	internalgrpc "github.com/cerbos/cerbos-sdk-go/internal/grpc"
)

var errMissingCredentials = errors.New("missing credentials: either set the CERBOS_HUB_CLIENT_ID and CERBOS_HUB_CLIENT_SECRET environment variables or use the WithCredentials option when creating the client")

type hubConfig struct {
	advancedConf *internalgrpc.Config
	credentials  hubCredentials
	apiEndpoint  string
}

type hubCredentials struct {
	clientID     string
	clientSecret string
	tokenSource  oauth2.TokenSource
}

type HubOpt func(*hubConfig)

// WithHubAPIEndpoint overrides the API endpoint.
func WithHubAPIEndpoint(endpoint string) HubOpt {
	return func(hubConf *hubConfig) {
		hubConf.apiEndpoint = endpoint
	}
}

// WithHubCredentials sets the access credentials for the client.
// If not provided, the credentials are read from CERBOS_HUB_CLIENT_ID and CERBOS_HUB_CLIENT_SECRET environment variables.
func WithHubCredentials(clientID, clientSecret string) HubOpt {
	return func(hubConf *hubConfig) {
		hubConf.credentials = hubCredentials{clientID: clientID, clientSecret: clientSecret}
	}
}

// WithHubTokenSource sets the token source for authentication.
func WithHubTokenSource(tokenSource oauth2.TokenSource) HubOpt {
	return func(hubConf *hubConfig) {
		hubConf.credentials = hubCredentials{tokenSource: tokenSource}
	}
}

// WithAdvancedOptions is only used for internal testing purposes. Don't use in production.
func WithAdvancedOptions(opts ...Opt) HubOpt {
	return func(hubConf *hubConfig) {
		hubConf.advancedConf = &internalgrpc.Config{}
		for _, o := range opts {
			o(hubConf.advancedConf)
		}
	}
}

type HubClient struct {
	storeClient *store.Client
}

// NewHubClient creates a client configured to interact with Cerbos Hub.
// Supply credentials using CERBOS_HUB_CLIENT_ID and CERBOS_HUB_CLIENT_SECRET environment variables or using the WithHubCredentials option.
func NewHubClient(opts ...HubOpt) (*HubClient, error) {
	hubConf := &hubConfig{
		apiEndpoint: "https://api.cerbos.cloud",
		credentials: hubCredentials{
			clientID:     os.Getenv("CERBOS_HUB_CLIENT_ID"),
			clientSecret: os.Getenv("CERBOS_HUB_CLIENT_SECRET"),
		},
	}

	for _, opt := range opts {
		opt(hubConf)
	}

	var creds *credentials.Credentials
	var err error
	switch {
	case hubConf.credentials.clientID != "" && hubConf.credentials.clientSecret != "":
		creds, err = credentials.New(hubConf.credentials.clientID, hubConf.credentials.clientSecret, "")
	case hubConf.credentials.tokenSource != nil:

		creds = credentials.NewFromTokenSource(hubConf.credentials.tokenSource)
	default:
		err = errMissingCredentials
	}

	if err != nil {
		return nil, err
	}

	baseConf := base.ClientConf{
		APIEndpoint: hubConf.apiEndpoint,
		Credentials: creds,
	}
	baseConf.SetDefaults()

	if hubConf.advancedConf != nil {
		baseConf.TLS, err = internalgrpc.MkTLSConfig(hubConf.advancedConf)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
	}

	h, err := hub.New(baseConf)
	if err != nil {
		return nil, err
	}

	sc, err := h.StoreClient()
	if err != nil {
		return nil, err
	}

	return &HubClient{storeClient: sc}, nil
}

func (hc *HubClient) StoreClient() *localhub.StoreClient {
	return localhub.NewStoreClient(hc.storeClient)
}
