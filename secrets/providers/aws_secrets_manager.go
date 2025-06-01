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

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/prometheus/client_golang/prometheus"
	commoncfg "github.com/prometheus/common/config"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/prometheus/alertmanager/secrets"
)

type SecretFetchErrorCategory int

type SecretFetchState int

const (
	Success SecretFetchState = iota
	Stale
	Error
)

const (
	Config SecretFetchErrorCategory = iota
	Unexpected
	None
)

var MinTimeInterval = 5 * time.Second

func (s SecretFetchState) String() string {
	switch s {
	case Success:
		return "success"
	case Stale:
		return "stale"
	case Error:
		return "error"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

func (s SecretFetchState) Value() float64 {
	return float64(s)
}

func (s SecretFetchErrorCategory) String() string {
	switch s {
	case Config:
		return "config"
	case Unexpected:
		return "unexpected"
	case None:
		return ""
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

func (s SecretFetchErrorCategory) Value() float64 {
	return float64(s)
}

var (
	AllSecretFetchStates          = []SecretFetchState{Success, Stale, Error}
	AllSecretFetchErrorCategories = []SecretFetchErrorCategory{Config, Unexpected, None}
)

type RoundTripperFn func(rt http.RoundTripper) (http.RoundTripper, error)

type AWSSecretsManagerProvider struct {
	mtx            sync.RWMutex
	fetchers       map[string]*secretFetcher
	logger         *slog.Logger
	reg            prometheus.Registerer
	ctx            context.Context
	RoundTripper   RoundTripperFn
	secretFetchers prometheus.Gauge

	newFetchers map[string]struct{}
}

func (a *AWSSecretsManagerProvider) fetchersCount() int {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	return len(a.fetchers)
}

func (a *AWSSecretsManagerProvider) validateARN(secretARN string) error {
	parsedARN, err := arn.Parse(secretARN)
	if err != nil {
		return err
	}
	if parsedARN.Service != "secretsmanager" {
		return errors.New("invalid service")
	}
	if parsedARN.Resource == "" {
		return errors.New("invalid resource")
	}
	if parsedARN.AccountID == "" {
		return errors.New("invalid account ID")
	}
	if parsedARN.Partition == "" {
		return errors.New("invalid partition")
	}
	return nil
}

func (a *AWSSecretsManagerProvider) Register(secret secrets.GenericSecret) secrets.SecretsFetcher {
	s := secret.AWSSecretsManagerConfig
	if err := a.validateARN(s.SecretARN); err != nil {
		a.logger.Error("invalid secret ARN", "error", err)
		return nil
	}
	if s.IsZero() {
		a.logger.Error("secret is nil. nothing to register")
		return nil
	}
	a.logger.Info("registering secret")
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if f, OK := a.fetchers[s.SecretARN]; OK {
		a.logger.Info("found an existing secret fetcher", "ARN", s.SecretARN)
		f.update(s.RefreshInterval)
		a.newFetchers[s.SecretARN] = struct{}{}
		return f
	}
	a.logger.Info("no secret fetcher found. creating a new one", "ARN", s.SecretARN)
	a.fetchers[s.SecretARN] = newSecretFetcher(a.ctx, a.logger, a.reg, a.RoundTripper, s)
	a.secretFetchers.Set(float64(len(a.fetchers)))
	a.newFetchers[s.SecretARN] = struct{}{}
	return a.fetchers[s.SecretARN]
}

func (a *AWSSecretsManagerProvider) Stop() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for name, fetcher := range a.fetchers {
		a.logger.Info("stopping secrets fetcher", "name", name)
		fetcher.AwaitStop()
		delete(a.fetchers, name)
		a.secretFetchers.Dec()
	}
	a.logger.Info("aws secrets manager providers stopped")
}

func (a *AWSSecretsManagerProvider) UpdateComplete() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.logger.Debug("Update begin", "fetchers", len(a.fetchers), "new fetchers", len(a.newFetchers))
	for name, fetcher := range a.fetchers {
		if _, OK := a.newFetchers[name]; !OK {
			fetcher.Stop()
			delete(a.fetchers, name)
			a.secretFetchers.Dec()
		}
	}
	// reset new fetchers
	a.newFetchers = make(map[string]struct{})
	a.logger.Debug("Update complete", "fetchers", len(a.fetchers))
}

func NewAWSSecretsManagerProvider(options secrets.SecretProviderOptions) *AWSSecretsManagerProvider {
	provider := &AWSSecretsManagerProvider{
		fetchers:    make(map[string]*secretFetcher),
		newFetchers: make(map[string]struct{}),
		logger:      options.Logger,
		reg:         options.Registerer,
		ctx:         options.Context,
		secretFetchers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "alertmanager_secrets_fetchers",
			Help: "Number of AWS Secrets Manager fetchers",
			ConstLabels: prometheus.Labels{
				"provider": "aws_secrets_manager",
			},
		}),
	}
	provider.reg.MustRegister(provider.secretFetchers)
	return provider
}

type secretFetcher struct {
	secretName    string
	secretConfig  secrets.AWSSecretsManagerConfig
	secrets       map[string]string
	mtx           sync.RWMutex
	logger        *slog.Logger
	reg           prometheus.Registerer
	ctx           context.Context
	client        AWSSecretsManagerOperations
	done          chan struct{}
	ticker        *time.Ticker
	roundTripper  RoundTripperFn
	asyncCh       chan struct{}
	lastRetrieved time.Time
	metrics       *SecretFetcherMetrics
	everSucceeded bool
	stopCh        chan struct{}
}

func newSecretFetcher(ctx context.Context, logger *slog.Logger, reg prometheus.Registerer, roundTripper RoundTripperFn, sc secrets.AWSSecretsManagerConfig) *secretFetcher {
	if sc.RefreshInterval <= 0 {
		sc.RefreshInterval = time.Minute * 5
	}
	parsedARN, _ := arn.Parse(sc.SecretARN)
	sf := &secretFetcher{
		secrets:       make(map[string]string),
		logger:        logger,
		reg:           reg,
		secretConfig:  sc,
		ctx:           ctx,
		done:          make(chan struct{}),
		roundTripper:  roundTripper,
		asyncCh:       make(chan struct{}),
		lastRetrieved: time.Time{},
		secretName:    parsedARN.Resource,
		stopCh:        make(chan struct{}),
	}
	sf.metrics = NewSecretFetcherMetrics(reg, sf.secretName)
	sf.ticker = time.NewTicker(sf.secretConfig.RefreshInterval)
	sf.createSecretsManagerClient()
	go sf.run()
	return sf
}

func (s *secretFetcher) RefreshCredentialsAsync() {
	s.asyncCh <- struct{}{}
}

func (s *secretFetcher) createSecretsManagerClient() {
	parsedARN, err := arn.Parse(s.secretConfig.SecretARN)
	if err != nil {
		s.logger.Error("unable to create secret manager client", "error", err)
		return
	}
	var httpClient *http.Client
	httpClient, err = commoncfg.NewClientFromConfig(commoncfg.DefaultHTTPClientConfig, "aws_secrets_manager")
	if err != nil {
		s.logger.Error("unable to create a new http client", "error", err)
		return
	}
	if s.roundTripper != nil {
		httpClient.Transport, err = s.roundTripper(httpClient.Transport)
		if err != nil {
			s.logger.Warn("unable to create round tripper. proceeding ", "error", err)
		}
	}

	config, err := awsconfig.LoadDefaultConfig(s.ctx, awsconfig.WithRegion(parsedARN.Region))
	config.HTTPClient = httpClient
	if err != nil {
		s.logger.Error("unable to load config", "error", err)
		return
	}
	s.client = secretsmanager.NewFromConfig(config)
}

func (s *secretFetcher) AwaitStop() {
	<-s.done
	s.metrics.Unregister(s.reg)
	s.logger.Info("secret fetcher stopped", "secret id", s.secretName)
}

func (s *secretFetcher) Stop() {
	close(s.stopCh)
	<-s.done
	s.metrics.Unregister(s.reg)
	s.logger.Info("secret fetcher stopped", "secret id", s.secretName)
}

func (s *secretFetcher) run() {
	defer close(s.done)
	defer s.ticker.Stop()
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.secretConfig.SecretARN),
	}
	s.retrieveSecret(input, "initial")
	for {
		select {
		case <-s.ticker.C:
			s.retrieveSecret(input, "periodic")
		case <-s.asyncCh:
			s.retrieveSecret(input, "async refresh")
		case <-s.stopCh:
			s.logger.Info("stopping secrets fetcher via stop signal")
			return
		case <-s.ctx.Done():
			s.logger.Info("stopping secrets fetcher via context cancellation")
			return
		}
	}
}

func (s *secretFetcher) resetAllStateMetrics() {
	for _, state := range AllSecretFetchStates {
		for _, category := range AllSecretFetchErrorCategories {
			s.metrics.secretState.WithLabelValues(state.String(), category.String()).Set(0)
		}
	}
}

func (s *secretFetcher) retrieveSecret(input *secretsmanager.GetSecretValueInput, reason string) {
	updateState := func(state SecretFetchState, category SecretFetchErrorCategory) {
		s.resetAllStateMetrics()
		if state == Error && s.everSucceeded {
			state = Stale
		}
		s.metrics.secretState.WithLabelValues(state.String(), category.String()).Set(state.Value())
	}
	if time.Since(s.lastRetrieved) < MinTimeInterval {
		s.logger.Info("not refreshing secret", "reason", "too soon")
		return
	}
	if s.ctx.Err() != nil {
		s.logger.Info("not refreshing secret", "reason", "context cancelled")
		return
	}
	if !s.lastRetrieved.IsZero() {
		s.metrics.timeSinceLastSuccessfulFetch.Set(float64(time.Since(s.lastRetrieved)))
	}
	s.logger.Info("fetching secret", "reason", reason, "secret", s.secretName)
	ctx, cancelFunc := context.WithTimeoutCause(context.Background(), 5*time.Second, errors.New("timed out while retrieving secret"))
	defer cancelFunc()
	if s.client == nil {
		s.logger.Error("secret manager client is nil", "arn", s.secretConfig.SecretARN)
		updateState(Error, Unexpected)
		return
	}
	retrievalTime := time.Now()
	result, err := s.client.GetSecretValue(ctx, input)
	if err != nil {
		s.logger.Error("unable to fetch secret for ARN", "arn", s.secretConfig.SecretARN, "error", err)
		s.metrics.secretFetchErrors.Inc()
		var re *awshttp.ResponseError
		category := Unexpected
		if errors.As(err, &re) && re.HTTPStatusCode()/100 == 4 {
			category = Config
		}
		updateState(Error, category)

		return
	}
	secretString := *result.SecretString
	var m map[string]string
	if err = json.Unmarshal([]byte(secretString), &m); err != nil {
		s.logger.Error("unable to unmarshal payload", "arn", s.secretConfig.SecretARN, "error", err)
		s.metrics.secretFetchErrors.Inc()
		updateState(Error, Config)
		return
	}
	s.logger.Debug("retrieved keys", "key count", len(m))
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.lastRetrieved = retrievalTime
	s.secrets = nil
	s.secrets = m
	s.metrics.secretFetchSuccess.Inc()
	s.everSucceeded = true
	updateState(Success, None)
}

func (s *secretFetcher) update(interval time.Duration) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.secretConfig.RefreshInterval = interval
	s.ticker.Reset(s.secretConfig.RefreshInterval)
}

func (s *secretFetcher) FetchSecret(_ context.Context, secret secrets.GenericSecret) (string, error) {
	sec := secret.AWSSecretsManagerConfig
	if sec.IsZero() {
		return "", errors.New("cannot fetch empty secret")
	}

	// Pre-check if SecretKey is empty to avoid unnecessary lock
	if sec.SecretKey == "" {
		return "", errors.New("secret key is empty")
	}

	s.mtx.RLock()
	value, exists := s.secrets[sec.SecretKey]
	s.mtx.RUnlock()
	if !exists {
		return "", errors.New(fmt.Sprintf("secret key %s not found", sec.SecretKey))
	}
	return value, nil
}

type AWSSecretsManagerSecretProviderDiscoveryConfig struct{}

func (a AWSSecretsManagerSecretProviderDiscoveryConfig) Name() string {
	return "aws_secrets_manager"
}

func (a AWSSecretsManagerSecretProviderDiscoveryConfig) NewSecretsProvider(options secrets.SecretProviderOptions) (secrets.SecretsProvider, error) {
	return NewAWSSecretsManagerProvider(options), nil
}

type SecretFetcherMetrics struct {
	secretFetchErrors            prometheus.Counter
	secretFetchSuccess           prometheus.Counter
	secretState                  *prometheus.GaugeVec
	timeSinceLastSuccessfulFetch prometheus.Gauge
}

func (sm *SecretFetcherMetrics) Unregister(reg prometheus.Registerer) {
	reg.Unregister(sm.secretFetchErrors)
	reg.Unregister(sm.secretFetchSuccess)
	reg.Unregister(sm.secretState)
	reg.Unregister(sm.timeSinceLastSuccessfulFetch)
}

func NewSecretFetcherMetrics(reg prometheus.Registerer, secretName string) *SecretFetcherMetrics {
	m := &SecretFetcherMetrics{
		secretFetchErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_remote_secret_fetch_failures_total",
			Help: "Total number of failed secret fetches",
			ConstLabels: prometheus.Labels{
				"secret_id": secretName,
				"provider":  "aws_secrets_manager",
			},
		}),
		secretFetchSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_remote_secret_fetch_success_total",
			Help: "Total number of successful secret fetches",
			ConstLabels: prometheus.Labels{
				"secret_id": secretName,
				"provider":  "aws_secrets_manager",
			},
		}),
		secretState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "alertmanager_remote_secret_state",
			Help: "State of the secret",
			ConstLabels: prometheus.Labels{
				"secret_id": secretName,
				"provider":  "aws_secrets_manager",
			},
		}, []string{"state", "category"}),
		timeSinceLastSuccessfulFetch: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "alertmanager_remote_secret_time_since_last_successful_fetch",
			Help: "Time since last successful secret fetch",
			ConstLabels: prometheus.Labels{
				"secret_id": secretName,
				"provider":  "aws_secrets_manager",
			},
		}),
	}
	if reg != nil {
		reg.MustRegister(
			m.secretFetchErrors,
			m.secretFetchSuccess,
			m.secretState,
			m.timeSinceLastSuccessfulFetch,
		)
	}
	return m
}

type AWSSecretsManagerOperations interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}
