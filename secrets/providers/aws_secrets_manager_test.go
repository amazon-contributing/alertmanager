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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/secrets"
)

func TestFetchSecret(t *testing.T) {
	tests := []struct {
		name          string
		secret        secrets.GenericSecret
		setupSecrets  map[string]string
		expectedValue string
		expectError   bool
	}{
		{
			name: "successful fetch",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
					SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
					SecretKey:       "test-secret",
					RefreshInterval: 5 * time.Millisecond,
				},
			},
			setupSecrets: map[string]string{
				"arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty": `
					{
						"test-secret": "secret-value"
					}
					`,
			},
			expectedValue: "secret-value",
			expectError:   false,
		},
		{
			name: "successful fetch multi-value",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
					SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
					SecretKey:       "test-secret",
					RefreshInterval: 5 * time.Millisecond,
				},
			},
			setupSecrets: map[string]string{
				"arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty": `
					{
						"test-secret": "secret-value",
						"test-secret2": "secret-value2"
					}
					`,
			},
			expectedValue: "secret-value",
			expectError:   false,
		},
		{
			name: "empty secret config",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{},
			},
			setupSecrets:  nil,
			expectedValue: "",
			expectError:   true,
		},
		{
			name: "empty secret key",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
					SecretKey: "",
				},
			},
			setupSecrets:  nil,
			expectedValue: "",
			expectError:   true,
		},
		{
			name: "non-existent secret key",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
					SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
					SecretKey:       "test-secret3",
					RefreshInterval: 5 * time.Millisecond,
				},
			},
			setupSecrets: map[string]string{
				"arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty": `
					{
						"test-secret": "secret-value",
						"test-secret2": "secret-value2"
					}
					`,
			},
			expectedValue: "",
			expectError:   true,
		},
		{
			name: "bad secret json",
			secret: secrets.GenericSecret{
				AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
					SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
					SecretKey:       "test-secret3",
					RefreshInterval: 5 * time.Millisecond,
				},
			},
			setupSecrets: map[string]string{
				"arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty": `
					{
						"test-secret": "secret-value"
						"test-secret2": "secret-value2"
					}
					`,
			},
			expectedValue: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeoutCause(context.Background(), 10*time.Millisecond, errors.New("timeout"))
			reg := prometheus.NewPedanticRegistry()
			fetcher := &secretFetcher{
				secrets:      make(map[string]string),
				logger:       promslog.NewNopLogger(),
				ctx:          ctx,
				secretConfig: tt.secret.AWSSecretsManagerConfig,
				ticker:       time.NewTicker(time.Second),
				client: &MockSecretsManagerClient{
					secrets: tt.setupSecrets,
				},
				done:          make(chan struct{}),
				asyncCh:       make(chan struct{}),
				lastRetrieved: time.Time{},
				metrics:       NewSecretFetcherMetrics(reg, tt.secret.AWSSecretsManagerConfig.SecretARN),
				reg:           reg,
			}
			fetcher.run()
			value, err := fetcher.FetchSecret(context.Background(), tt.secret)
			cancel()
			fetcher.AwaitStop()
			if tt.expectError {
				require.Error(t, err)
				require.Empty(t, value)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

func TestNewSecretFetcherMetrics_Error(t *testing.T) {
	fetcher, reg := setupFetcher()
	fetcher.client = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("test error")
		},
	}
	// Call retrieveSecret
	secretID := "test-secret"
	input := &secretsmanager.GetSecretValueInput{SecretId: &secretID}
	fetcher.retrieveSecret(input, "testing")
	errorCount := testutil.ToFloat64(fetcher.metrics.secretFetchErrors)
	require.Equal(t, 1.0, errorCount, "Error counter should be 1")
	require.False(t, fetcher.everSucceeded, "everSucceeded should still be false")

	metricFamily, err := reg.Gather()
	require.NoError(t, err)

	// Find and check the state metric
	var stateValue float64
	for _, mf := range metricFamily {
		if mf.GetName() == "alertmanager_remote_secret_state" {
			for _, m := range mf.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "state" && l.GetValue() == "error" {
						stateValue = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	require.Equal(t, float64(Error), stateValue, "State should be Error (2)")
}

func TestNewSecretFetcherMetrics_Success(t *testing.T) {
	fetcher, reg := setupFetcher()

	// Mock successful secret retrieval
	secretData, _ := json.Marshal(map[string]string{"key": "value"})
	secretStr := string(secretData)
	fetcher.client = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &secretStr,
			}, nil
		},
	}
	// Call retrieveSecret
	secretID := "test-secret"
	input := &secretsmanager.GetSecretValueInput{SecretId: &secretID}
	fetcher.retrieveSecret(input, "testing")
	successCount := testutil.ToFloat64(fetcher.metrics.secretFetchSuccess)
	require.Equal(t, 1.0, successCount, "Success counter should be 1")
	require.True(t, fetcher.everSucceeded, "everSucceeded should be true")

	metricFamily, err := reg.Gather()
	require.NoError(t, err)

	// Find and check the state metric
	var stateValue float64
	for _, mf := range metricFamily {
		if mf.GetName() == "alertmanager_remote_secret_state" {
			for _, m := range mf.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "state" && l.GetValue() == "success" {
						stateValue = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	require.Equal(t, float64(Success), stateValue, "State should be Success (0)")
}

func TestNewSecretFetcherMetrics_Stale(t *testing.T) {
	MinTimeInterval = 5 * time.Millisecond
	defer func() {
		MinTimeInterval = 5 * time.Second
	}()
	// Mock successful secret retrieval
	secretData, _ := json.Marshal(map[string]string{"key": "value"})
	secretStr := string(secretData)

	fetcher, reg := setupFetcher()
	fetcher.client = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &secretStr,
			}, nil
		},
	}
	// Call retrieveSecret
	secretID := "test-secret"
	input := &secretsmanager.GetSecretValueInput{SecretId: &secretID}
	fetcher.retrieveSecret(input, "testing")
	successCount := testutil.ToFloat64(fetcher.metrics.secretFetchSuccess)
	require.Equal(t, 1.0, successCount, "Success counter should be 1")
	require.True(t, fetcher.everSucceeded, "everSucceeded should be true")

	// Now mock a failure
	fetcher.client = &MockSecretsManagerClient{
		GetSecretValueFunc: func(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("test error")
		},
	}

	time.Sleep(MinTimeInterval)
	fetcher.retrieveSecret(input, "testing")

	// Verify stale state (should be Stale since everSucceeded is true)
	errorCount := testutil.ToFloat64(fetcher.metrics.secretFetchErrors)
	require.Equal(t, 1.0, errorCount, "Error counter should be 1")

	metricFamily, err := reg.Gather()
	require.NoError(t, err)

	// Find and check the state metric
	var stateValue float64
	for _, mf := range metricFamily {
		if mf.GetName() == "alertmanager_remote_secret_state" {
			for _, m := range mf.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "state" && l.GetValue() == "stale" {
						stateValue = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	require.Equal(t, float64(Stale), stateValue, "State should be Stale (1)")
	require.True(t, fetcher.everSucceeded, "everSucceeded should still be true")
}

func TestAWSSecretsManagerSecretProviderDiscoveryConfig(t *testing.T) {
	config := AWSSecretsManagerSecretProviderDiscoveryConfig{}

	t.Run("test name", func(t *testing.T) {
		require.Equal(t, "aws_secrets_manager", config.Name())
	})

	var provider *AWSSecretsManagerProvider
	t.Run("test provider creation", func(t *testing.T) {
		options := secrets.SecretProviderOptions{
			Logger:     promslog.NewNopLogger(),
			Registerer: prometheus.NewRegistry(),
			Context:    context.Background(),
		}

		p, err := config.NewSecretsProvider(options)

		require.NoError(t, err)
		require.NotNil(t, p)

		// Type assertion to ensure correct type
		pt, ok := p.(*AWSSecretsManagerProvider)
		provider = pt
		require.True(t, ok)
	})

	t.Run("test register secret", func(t *testing.T) {
		fetcher := provider.Register(secrets.GenericSecret{
			AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
				SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
				SecretKey:       "test-secret",
				RefreshInterval: 5 * time.Millisecond,
			},
		})
		require.NotNil(t, fetcher)
		require.Equal(t, 1, provider.fetchersCount())
	})

	t.Run("test register second secret", func(t *testing.T) {
		fetcher := provider.Register(secrets.GenericSecret{
			AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
				SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty2",
				SecretKey:       "test-secret",
				RefreshInterval: 5 * time.Millisecond,
			},
		})
		require.NotNil(t, fetcher)
		require.Equal(t, 2, provider.fetchersCount())
	})

	t.Run("test register same secret again", func(t *testing.T) {
		fetcher := provider.Register(secrets.GenericSecret{
			AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
				SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty2",
				SecretKey:       "test-secret",
				RefreshInterval: 5 * time.Millisecond,
			},
		})
		require.NotNil(t, fetcher)
		require.Equal(t, 2, provider.fetchersCount())
	})

	t.Run("test register secret with bad ARN", func(t *testing.T) {
		fetcher := provider.Register(secrets.GenericSecret{
			AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
				SecretARN:       "arn:aws::us-west-2:123456789:secret:receiver-pager-duty2",
				SecretKey:       "test-secret",
				RefreshInterval: 5 * time.Millisecond,
			},
		})
		require.Nil(t, fetcher)
		require.Equal(t, 2, provider.fetchersCount())
	})
}

func TestRegisterSecret(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	options := secrets.SecretProviderOptions{
		Logger:     promslog.NewNopLogger(),
		Registerer: reg,
		Context:    ctx,
	}
	provider := NewAWSSecretsManagerProvider(options)
	secretOne := secrets.GenericSecret{
		AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
			SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
			SecretKey:       "key1",
			RefreshInterval: 5 * time.Millisecond,
		},
	}
	secretOneCopy := secrets.GenericSecret{
		AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
			SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty",
			SecretKey:       "key2",
			RefreshInterval: 5 * time.Millisecond,
		},
	}
	provider.Register(secretOne)
	require.Equal(t, 1, provider.fetchersCount())

	provider.Register(secretOneCopy)
	require.Equal(t, 1, provider.fetchersCount())

	secretTwo := secrets.GenericSecret{
		AWSSecretsManagerConfig: secrets.AWSSecretsManagerConfig{
			SecretARN:       "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty-2",
			SecretKey:       "key1",
			RefreshInterval: 5 * time.Millisecond,
		},
	}
	provider.Register(secretTwo)
	require.Equal(t, 2, provider.fetchersCount())
	provider.UpdateComplete()
	require.Equal(t, 2, provider.fetchersCount())

	// simulate an update
	provider.Register(secretTwo)
	provider.UpdateComplete()
	require.Equal(t, 1, provider.fetchersCount())
	cancel()
	provider.Stop()
}

type MockSecretsManagerClient struct {
	secretsmanager.Client
	secrets            map[string]string
	GetSecretValueFunc func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *MockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.GetSecretValueFunc != nil {
		return m.GetSecretValueFunc(ctx, params, optFns...)
	}
	secretKey := *params.SecretId
	if secretValue, ok := m.secrets[secretKey]; ok {
		return &secretsmanager.GetSecretValueOutput{
			SecretString: &secretValue,
		}, nil
	}
	return nil, errors.New("not found")
}

func setupFetcher() (*secretFetcher, *prometheus.Registry) {
	reg := prometheus.NewPedanticRegistry()
	secretARN := "arn:aws:secretsmanager:us-west-2:123456789:secret:receiver-pager-duty"
	return &secretFetcher{
		secrets: make(map[string]string),
		logger:  promslog.NewNopLogger(),
		secretConfig: secrets.AWSSecretsManagerConfig{
			SecretARN:       secretARN,
			SecretKey:       "test-secret",
			RefreshInterval: 5 * time.Millisecond,
		},
		ticker:        time.NewTicker(time.Second),
		done:          make(chan struct{}),
		asyncCh:       make(chan struct{}),
		lastRetrieved: time.Time{},
		ctx:           context.Background(),
		metrics:       NewSecretFetcherMetrics(reg, secretARN),
	}, reg
}
