package secrets

import (
	"context"
	"errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"log/slog"
	"sync"
)

var (
	AWS_SECRETS_MANAGER_PROVIDER = "aws_secrets_manager"
)

type SecretsFetcher interface {
	FetchSecret(ctx context.Context, secret *GenericSecret) (string, error)
	Stop()
}

type SecretsProvider interface {
	Register(secret *GenericSecret) SecretsFetcher
	Stop()
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

func (s *SecretsProviderRegistry) Register(config SecretProviderDiscoveryConfig) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.logger.Info("registering secret providers", "name", config.Name())
	s.configs[config.Name()] = config
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
	s.logger.Info("stopped secrets providers registry")
}

func (s *SecretsProviderRegistry) RegisterSecret(secret *GenericSecret) (SecretsFetcher, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	s.logger.Info("registering secret")
	if secret.AWSSecretsManagerConfig != nil {
		s.logger.Info("registering aws_secret_manager secret")
		return s.providers[AWS_SECRETS_MANAGER_PROVIDER].Register(secret), nil
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

	HTTPClientOptions []config.HTTPClientOption

	Context context.Context
}
