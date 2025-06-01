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
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestGenericSecret_String(t *testing.T) {
	tests := []struct {
		name     string
		gs       GenericSecret
		marshal  bool
		expected string
	}{
		{
			name:     "with marshal secret value true",
			gs:       GenericSecret{Inline: Inline{Secret: "test-secret"}},
			marshal:  true,
			expected: "test-secret",
		},
		{
			name:     "with marshal secret value false",
			gs:       GenericSecret{Inline: Inline{Secret: "test-secret"}},
			marshal:  false,
			expected: "<secret>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MarshalSecretValue = tt.marshal
			if got, err := tt.gs.MarshalYAML(); err != nil && got != tt.expected {
				t.Errorf("GenericSecret.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenericSecret_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		gs       GenericSecret
		expected bool
	}{
		{
			name:     "empty generic secret",
			gs:       GenericSecret{},
			expected: true,
		},
		{
			name: "non-empty inline secret",
			gs: GenericSecret{
				Inline: Inline{Secret: "test-secret"},
			},
			expected: false,
		},
		{
			name: "non-empty AWS config",
			gs: GenericSecret{
				AWSSecretsManagerConfig: AWSSecretsManagerConfig{
					SecretARN: "arn:aws:secretsmanager:test",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.gs.IsZero(); got != tt.expected {
				t.Errorf("GenericSecret.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenericSecret_MarshalYAML(t *testing.T) {
	type checkFn func(t *testing.T, expected, got interface{})
	tests := []struct {
		name     string
		gs       GenericSecret
		marshal  bool
		expected interface{}
		wantErr  bool
		check    checkFn
	}{
		{
			name: "marshal with secret value true",
			gs: GenericSecret{
				Inline: Inline{Secret: "test-secret"},
			},
			marshal:  true,
			expected: "test-secret",
			wantErr:  false,
			check: func(t *testing.T, expected, got interface{}) {
				if got.(string) != expected {
					t.Errorf("GenericSecret.MarshalYAML() = %v, want %v", got, expected)
				}
			},
		},
		{
			name: "marshal with secret value false",
			gs: GenericSecret{
				Inline: Inline{Secret: "test-secret"},
			},
			marshal:  false,
			expected: "<secret>",
			wantErr:  false,
			check: func(t *testing.T, expected, got interface{}) {
				if got.(string) != expected {
					t.Errorf("GenericSecret.MarshalYAML() = %v, want %v", got, expected)
				}
			},
		},
		{
			name:     "marshal zero value",
			gs:       GenericSecret{},
			marshal:  false,
			expected: "",
			wantErr:  false,
			check: func(t *testing.T, expected, got interface{}) {
				if got.(string) != expected {
					t.Errorf("GenericSecret.MarshalYAML() = %v, want %v", got, expected)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MarshalSecretValue = tt.marshal
			got, err := tt.gs.MarshalYAML()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericSecret.MarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.check(t, tt.expected, got)
		})
	}
}

func TestAWSSecretsManagerConfig_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		config   AWSSecretsManagerConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   AWSSecretsManagerConfig{},
			expected: true,
		},
		{
			name: "config with ARN only",
			config: AWSSecretsManagerConfig{
				SecretARN: "arn:aws:secretsmanager:test",
			},
			expected: false,
		},
		{
			name: "config with key only",
			config: AWSSecretsManagerConfig{
				SecretKey: "test-key",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsZero(); got != tt.expected {
				t.Errorf("AWSSecretsManagerConfig.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenericSecret_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected GenericSecret
		wantErr  bool
	}{
		{
			name:  "inline string secret",
			input: "test-secret",
			expected: GenericSecret{
				Inline: Inline{Secret: "test-secret"},
			},
			wantErr: false,
		},
		{
			name: "aws secrets manager config",
			input: `
aws_secrets_manager:
  secret_arn: arn:aws:secretsmanager:test
  secret_key: test-key
  refresh_interval: 1h
`,
			expected: GenericSecret{
				AWSSecretsManagerConfig: AWSSecretsManagerConfig{
					SecretARN:       "arn:aws:secretsmanager:test",
					SecretKey:       "test-key",
					RefreshInterval: time.Hour,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got GenericSecret
			err := yaml.Unmarshal([]byte(tt.input), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericSecret.UnmarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Compare the relevant fields
				if got.Inline.Secret != tt.expected.Inline.Secret {
					t.Errorf("Inline.Secret = %v, want %v", got.Inline.Secret, tt.expected.Inline.Secret)
				}
				if got.AWSSecretsManagerConfig.SecretARN != tt.expected.AWSSecretsManagerConfig.SecretARN {
					t.Errorf("SecretARN = %v, want %v", got.AWSSecretsManagerConfig.SecretARN, tt.expected.AWSSecretsManagerConfig.SecretARN)
				}
			}
		})
	}
}
