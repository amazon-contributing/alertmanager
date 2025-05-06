package secrets

import (
	"errors"
	"time"
)

type GenericSecret struct {
	AWSSecretsManagerConfig *AWSSecretsManagerConfig `yaml:"aws_secrets_manager" json:"aws_secrets_manager_config"`
}

// TODO implement this correctly
func (gs *GenericSecret) String() string {
	return ""
}

// TODO implement Marshal and JSON equivalent methods
func (gs *GenericSecret) UnmarshalYAML(unmarshalFn func(any) error) error {
	var inlineForm string
	if err := unmarshalFn(&inlineForm); err == nil {
		return errors.New("inline form is not supported")
	}
	type plain GenericSecret
	// We need to do this to avoid infinite recursion.
	return unmarshalFn((*plain)(gs))
}

type AWSSecretsManagerConfig struct {
	SecretARN       string        `yaml:"secret_arn"`
	SecretKey       string        `yaml:"secret_key"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}
