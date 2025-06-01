// Copyright 2019 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/stretchr/testify/require"
)

func TestNewSecretsProviderRegistry(t *testing.T) {
	logger := slog.Default()
	reg := prometheus.NewRegistry()
	registry := NewSecretsProviderRegistry(logger, reg)

	require.NotNil(t, registry)
	require.NotNil(t, registry.providers)
	require.NotNil(t, registry.configs)
	require.NotNil(t, registry.logger)
	require.NotNil(t, registry.reg)
}

func TestNewSecretsProviderRegistryInit(t *testing.T) {
	logger := slog.Default()
	reg := prometheus.NewRegistry()

	tests := []struct {
		name            string
		discoveryConfig SecretProviderDiscoveryConfig
		wantErr         bool
		registries      []string
	}{
		{
			name:            "successful initialization",
			discoveryConfig: MockSecretProviderDiscoveryConfig{},
			wantErr:         false,
			registries:      []string{"mock secret provider"},
		},
		{
			name:            "unsuccessful initialization",
			discoveryConfig: nil,
			wantErr:         true,
		},
		{
			name:            "unsuccessful initialization with no name provider",
			discoveryConfig: MockSecretProviderDiscoveryConfigNoName{},
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewSecretsProviderRegistry(logger, reg)
			err := registry.Register(tt.discoveryConfig)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			registry.Init()

			for _, r := range tt.registries {
				require.NotNil(t, registry.providers[r])
			}
		})
	}
}

func TestRegisterSecret(t *testing.T) {
	tests := []struct {
		name          string
		secret        GenericSecret
		setupRegistry func(*SecretsProviderRegistry)
		wantErr       bool
		errMessage    string
	}{
		{
			name: "successful AWS secrets manager registration",
			secret: GenericSecret{
				AWSSecretsManagerConfig: AWSSecretsManagerConfig{
					SecretARN: "arn:aws:secretsmanager:region:123456789012:secret:my-secret",
				},
			},
			setupRegistry: func(registry *SecretsProviderRegistry) {
				mockProvider := &MockSecretsProvider{}
				registry.providers[AWSSecretsManagerProviderName] = mockProvider
			},
			wantErr: false,
		},
		{
			name: "AWS secrets manager provider not initialized",
			secret: GenericSecret{
				AWSSecretsManagerConfig: AWSSecretsManagerConfig{
					SecretARN: "arn:aws:secretsmanager:region:123456789012:secret:my-secret",
				},
			},
			setupRegistry: func(registry *SecretsProviderRegistry) {},
			wantErr:       true,
			errMessage:    "AWS secrets manager provider not initialized",
		},
		{
			name: "successful inline secret registration",
			secret: GenericSecret{
				Inline: Inline{
					Secret: "test-secret",
				},
			},
			setupRegistry: func(registry *SecretsProviderRegistry) {},
			wantErr:       false,
		},
		{
			name:          "no valid secret configuration",
			secret:        GenericSecret{},
			setupRegistry: func(registry *SecretsProviderRegistry) {},
			wantErr:       true,
			errMessage:    "no secrets fetcher found for the given secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &SecretsProviderRegistry{
				logger:    slog.Default(),
				providers: make(map[string]SecretsProvider),
			}
			tt.setupRegistry(registry)

			fetcher, err := registry.RegisterSecret(tt.secret)

			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, tt.errMessage, err.Error())
				require.Nil(t, fetcher)
			} else {
				require.NoError(t, err)
				require.NotNil(t, fetcher)
			}
			registry.Stop()
		})
	}
}

func TestSecretsProviderRegistry_Stop(t *testing.T) {
	t.Run("stop all providers", func(t *testing.T) {
		registry := NewSecretsProviderRegistry(promslog.NewNopLogger(), prometheus.NewPedanticRegistry())
		sp1 := &MockSecretsProvider{}
		sp2 := &MockSecretsProvider{}
		discoveryconfig1 := &MockCustomizableSecretProviderDiscoveryConfig{
			ProviderName:    "provider-1",
			SecretsProvider: sp1,
		}
		discoveryconfig2 := &MockCustomizableSecretProviderDiscoveryConfig{
			ProviderName:    "provider-2",
			SecretsProvider: sp2,
		}
		err := registry.Register(discoveryconfig1)
		require.NoError(t, err)
		err = registry.Register(discoveryconfig2)
		require.NoError(t, err)
		registry.Init()
		registry.Stop()
		require.Nil(t, registry.providers)
		require.True(t, sp1.Stopped)
		require.True(t, sp2.Stopped)
	})
}

func TestInlineSecretsFetcher(t *testing.T) {
	tests := []struct {
		name    string
		secret  GenericSecret
		want    string
		wantErr bool
	}{
		{
			name: "fetch inline secret successfully",
			secret: GenericSecret{
				Inline: Inline{
					Secret: "test-secret-value",
				},
			},
			want:    "test-secret-value",
			wantErr: false,
		},
		{
			name: "fetch empty inline secret",
			secret: GenericSecret{
				Inline: Inline{
					Secret: "",
				},
			},
			want:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := InlineSecretsFetcher{}
			got, err := fetcher.FetchSecret(context.Background(), tt.secret)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

type MockSecretsProvider struct {
	Stopped bool
}

func (m *MockSecretsProvider) Stop() {
	m.Stopped = true
}

func (m *MockSecretsProvider) Register(secret GenericSecret) SecretsFetcher {
	return &MockSecretsFetcher{}
}

func (m *MockSecretsProvider) UpdateComplete() {}

type MockSecretsFetcher struct{}

func (m *MockSecretsFetcher) FetchSecret(ctx context.Context, secret GenericSecret) (string, error) {
	return "", nil
}

func (m *MockSecretsFetcher) RefreshCredentialsAsync() {}

func (m *MockSecretsFetcher) Stop() {}

func (m *MockSecretsFetcher) AwaitStop() {}

type MockSecretProviderDiscoveryConfig struct {
	wantErr bool
}

func (m MockSecretProviderDiscoveryConfig) Name() string {
	return "mock secret provider"
}

func (m MockSecretProviderDiscoveryConfig) NewSecretsProvider(options SecretProviderOptions) (SecretsProvider, error) {
	if m.wantErr {
		return nil, errors.New("unable to initialize secrets provider")
	}
	return &MockSecretsProvider{}, nil
}

type MockSecretProviderDiscoveryConfigNoName struct{}

func (m MockSecretProviderDiscoveryConfigNoName) Name() string {
	return ""
}

func (m MockSecretProviderDiscoveryConfigNoName) NewSecretsProvider(options SecretProviderOptions) (SecretsProvider, error) {
	panic("not implemented")
}

type MockCustomizableSecretProviderDiscoveryConfig struct {
	ProviderName    string
	SecretsProvider SecretsProvider
}

func (m MockCustomizableSecretProviderDiscoveryConfig) Name() string {
	return m.ProviderName
}

func (m MockCustomizableSecretProviderDiscoveryConfig) NewSecretsProvider(options SecretProviderOptions) (SecretsProvider, error) {
	return m.SecretsProvider, nil
}
