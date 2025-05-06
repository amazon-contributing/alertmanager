package providers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/prometheus/alertmanager/secrets"
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"sync"
	"time"
)

//TODO metrics

type AWSSecretsManagerProvider struct {
	mtx      sync.RWMutex
	fetchers map[string]*secretFetcher
	logger   *slog.Logger
	reg      prometheus.Registerer
	ctx      context.Context
}

func (a *AWSSecretsManagerProvider) Register(secret *secrets.GenericSecret) secrets.SecretsFetcher {
	s := secret.AWSSecretsManagerConfig
	if s == nil {
		a.logger.Error("secret is nil. nothing to register")
		return nil
	}
	a.logger.Info("registering secret")
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if f, OK := a.fetchers[s.SecretARN]; OK {
		a.logger.Info("found an existing secret fetcher")
		f.update(s.RefreshInterval)
		return f
	}
	a.logger.Info("no secret fetcher found. creating a new one")
	a.fetchers[s.SecretARN] = newSecretFetcher(a.ctx, a.logger, a.reg, s.SecretARN, s.RefreshInterval)
	return a.fetchers[s.SecretARN]
}

func (a *AWSSecretsManagerProvider) Stop() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for name, fetcher := range a.fetchers {
		a.logger.Info("stopping secrets fetcher", "name", name)
		fetcher.Stop()
	}
	a.logger.Info("aws secrets manager providers stopped")
}

type secretFetcher struct {
	secrets      map[string]string
	mtx          sync.RWMutex
	logger       *slog.Logger
	reg          prometheus.Registerer
	arn          string
	interval     time.Duration
	ctx          context.Context
	client       *secretsmanager.Client
	done         chan struct{}
	ticker       *time.Ticker
	initialFetch bool
}

func newSecretFetcher(ctx context.Context, logger *slog.Logger, reg prometheus.Registerer, arn string, interval time.Duration) *secretFetcher {
	sf := &secretFetcher{
		secrets:  make(map[string]string),
		logger:   logger,
		reg:      reg,
		arn:      arn,
		interval: interval,
		ctx:      ctx,
		done:     make(chan struct{}),
		ticker:   time.NewTicker(interval),
	}
	sf.createSecretsManagerClient()
	go sf.run()
	return sf
}

func (s *secretFetcher) createSecretsManagerClient() {
	parsedARN, err := arn.Parse(s.arn)
	if err != nil {
		s.logger.Error("unable to create secret manager client", err)
		return
	}
	config, err := awsconfig.LoadDefaultConfig(s.ctx, awsconfig.WithRegion(parsedARN.Region))
	if err != nil {
		s.logger.Error("unable to load config", err)
		return
	}
	s.client = secretsmanager.NewFromConfig(config)
}

func (s *secretFetcher) Stop() {
	<-s.done
	s.logger.Info("secret fetcher stopped")
}

func (s *secretFetcher) run() {
	defer close(s.done)
	defer s.ticker.Stop()
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.arn),
	}
	s.logger.Debug("fetch secret", "reason", "initial")
	s.retrieveSecret(input)
	s.initialFetch = true
	for {
		select {
		case <-s.ticker.C:
			s.logger.Debug("fetching secret", "reason", "periodic")
			s.retrieveSecret(input)
			s.initialFetch = true
		case <-s.ctx.Done():
			s.logger.Info("stopping secrets fetcher")
			return
		}
	}
}

func (s *secretFetcher) retrieveSecret(input *secretsmanager.GetSecretValueInput) {
	result, err := s.client.GetSecretValue(s.ctx, input)
	if err != nil {
		s.logger.Error("unable to fetch secret for ARN", "arn", s.arn, "error", err)
		return
	}
	secretString := *result.SecretString
	var m map[string]string
	if err = json.Unmarshal([]byte(secretString), &m); err != nil {
		s.logger.Error("unable to unmarshal payload", "arn", s.arn, "error", err)
		return
	}
	s.logger.Debug("retrieved keys", "key count", len(m))
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.secrets = nil
	s.secrets = m
}

func (s *secretFetcher) update(interval time.Duration) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.interval > interval {
		s.interval = interval
		s.ticker.Reset(s.interval)
	}
}

func (s *secretFetcher) FetchSecret(_ context.Context, secret *secrets.GenericSecret) (string, error) {
	sec := secret.AWSSecretsManagerConfig
	if sec == nil {
		return "", errors.New("cannot fetch empty secret")
	}

	s.mtx.RLock()
	value, exists := s.secrets[sec.SecretKey]
	s.mtx.RUnlock()
	if !exists {
		return "", errors.New("secret not found")
	}
	return value, nil
}

type AWSSecretsManagerSecretProviderDiscoveryConfig struct {
}

func (a AWSSecretsManagerSecretProviderDiscoveryConfig) Name() string {
	return "aws_secrets_manager"
}

func (a AWSSecretsManagerSecretProviderDiscoveryConfig) NewSecretsProvider(options secrets.SecretProviderOptions) (secrets.SecretsProvider, error) {
	return &AWSSecretsManagerProvider{
		fetchers: make(map[string]*secretFetcher),
		logger:   options.Logger,
		reg:      options.Registerer,
		ctx:      options.Context,
	}, nil
}
