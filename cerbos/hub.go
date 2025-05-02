// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"errors"
	"os"

	localhub "github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/cerbos/cloud-api/hub"
	"github.com/cerbos/cloud-api/store"
)

var errMissingCredentials = errors.New("missing credentials: either set the CERBOS_HUB_CLIENT_ID and CERBOS_HUB_CLIENT_SECRET environment variables or use the WithCredentials option when creating the client")

type hubConfig struct {
	apiEndpoint string
	credentials hubCredentials
}

type hubCredentials struct {
	clientID     string
	clientSecret string
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

	if hubConf.credentials.clientID == "" || hubConf.credentials.clientSecret == "" {
		return nil, errMissingCredentials
	}

	credentials, err := credentials.New(hubConf.credentials.clientID, hubConf.credentials.clientSecret, "")
	if err != nil {
		return nil, err
	}

	baseConf := base.ClientConf{
		APIEndpoint: hubConf.apiEndpoint,
		Credentials: credentials,
	}
	baseConf.SetDefaults()

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
