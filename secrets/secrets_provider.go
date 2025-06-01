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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var AWSSecretsManagerProviderName = "aws_secrets_manager"

type SecretsFetcher interface {
	FetchSecret(ctx context.Context, secret GenericSecret) (string, error)
	RefreshCredentialsAsync()
	Stop()
	AwaitStop()
}

type SecretsProvider interface {
	Register(secret GenericSecret) SecretsFetcher
	Stop()
	UpdateComplete()
}

type SecretsProviderRegistry struct {
	mtx       sync.RWMutex
	providers map[string]SecretsProvider
	logger    *slog.Logger
	reg       prometheus.Registerer
	configs   map[string]SecretProviderDiscoveryConfig
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewSecretsProviderRegistry(logger *slog.Logger, reg prometheus.Registerer) *SecretsProviderRegistry {
	registry := &SecretsProviderRegistry{
		providers: make(map[string]SecretsProvider),
		configs:   make(map[string]SecretProviderDiscoveryConfig),
		logger:    logger,
		reg:       reg,
	}
	return registry
}

func (s *SecretsProviderRegistry) Register(config SecretProviderDiscoveryConfig) error {
	if config == nil {
		return errors.New("nil config provided")
	}
	name := config.Name()
	if name == "" {
		return errors.New("empty provider name")
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.logger.Info("registering secret provider", "name", config.Name())
	s.configs[config.Name()] = config
	return nil
}

func (s *SecretsProviderRegistry) Init() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	for name, providerConfig := range s.configs {
		s.logger.Info("initializing secret providers", "name", name)
		provider, err := providerConfig.NewSecretsProvider(SecretProviderOptions{
			Logger:     s.logger,
			Registerer: s.reg,
			Context:    s.ctx,
		})
		if err != nil {
			s.logger.Error("unable to initialize secrets provider", "name", name, "error", err.Error())
			continue
		}
		s.providers[name] = provider
	}
}

func (s *SecretsProviderRegistry) UpdateComplete() {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	for name, provider := range s.providers {
		s.logger.Info("update complete invoked on provider", "name", name)
		provider.UpdateComplete()
	}
}

func (s *SecretsProviderRegistry) Stop() {
	if s == nil {
		return
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.cancel == nil {
		return
	}
	s.cancel()
	s.cancel = nil
	for name, provider := range s.providers {
		s.logger.Info("stopping secrets providers", "name", name)
		provider.Stop()
	}
	s.providers = nil
	s.logger.Info("stopped secrets providers registry")
}

func (s *SecretsProviderRegistry) RegisterSecret(secret GenericSecret) (SecretsFetcher, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	s.logger.Info("registering secret")
	if !secret.AWSSecretsManagerConfig.IsZero() {
		provider, exists := s.providers[AWSSecretsManagerProviderName]
		if !exists {
			return nil, errors.New("AWS secrets manager provider not initialized")
		}
		s.logger.Info("registering aws_secret_manager secret")
		return provider.Register(secret), nil
	}
	if secret.Inline.Secret != "" {
		return InlineSecretsFetcher{}, nil
	}
	return nil, errors.New("no secrets fetcher found for the given secret")
}

type SecretProviderDiscoveryConfig interface {
	// Name returns the name of the discovery mechanism.
	Name() string

	NewSecretsProvider(SecretProviderOptions) (SecretsProvider, error)
}

type SecretProviderOptions struct {
	Logger *slog.Logger

	// A registerer for the SecretProvider's metrics.
	Registerer prometheus.Registerer

	Context context.Context
}

type InlineSecretsFetcher struct{}

func (i InlineSecretsFetcher) FetchSecret(ctx context.Context, secret GenericSecret) (string, error) {
	return secret.Inline.Secret, nil
}

func (i InlineSecretsFetcher) RefreshCredentialsAsync() {}
func (i InlineSecretsFetcher) Stop()                    {}
func (i InlineSecretsFetcher) AwaitStop()               {}
