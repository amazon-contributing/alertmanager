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
	"encoding/json"
	"gopkg.in/yaml.v2"
	"time"
)

var MarshalSecretValue = false

const secretToken = "<secret>"

type GenericSecret struct {
	Inline                  Inline                  `yaml:",inline,omitempty" json:",inline,omitempty"`
	AWSSecretsManagerConfig AWSSecretsManagerConfig `yaml:"aws_secrets_manager,omitempty" json:"aws_secrets_manager_config,omitempty"`
}

func (gs GenericSecret) IsZero() bool {
	return gs.Inline.Secret == "" && gs.AWSSecretsManagerConfig.IsZero()
}

func (gs *GenericSecret) UnmarshalYAML(unmarshalFn func(any) error) error {
	var inlineForm string
	if err := unmarshalFn(&inlineForm); err == nil {
		gs.Inline = Inline{inlineForm}
		return nil
	}
	type plain GenericSecret
	// We need to do this to avoid infinite recursion.
	return unmarshalFn((*plain)(gs))
}

func (gs GenericSecret) MarshalYAML() (interface{}, error) {
	if MarshalSecretValue {
		if gs.Inline.Secret != "" {
			return gs.Inline.Secret, nil
		}
		type plain GenericSecret
		return yaml.Marshal((plain)(gs))
	}
	if gs.IsZero() {
		return "", nil
	}
	return secretToken, nil
}

func (gs GenericSecret) MarshalJSON() ([]byte, error) {
	if MarshalSecretValue {
		if gs.Inline.Secret != "" {
			return []byte(gs.Inline.Secret), nil
		}
		type plain GenericSecret
		return json.Marshal((plain)(gs))
	}
	if gs.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(secretToken)
}

type AWSSecretsManagerConfig struct {
	SecretARN       string        `yaml:"secret_arn" json:"secret_arn"`
	SecretKey       string        `yaml:"secret_key" json:"secret_key"`
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
}

func (a AWSSecretsManagerConfig) IsZero() bool {
	return a.SecretARN == "" && a.SecretKey == ""
}

type Inline struct {
	Secret string
}
