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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"github.com/prometheus/alertmanager/secrets"
)

type AMPAWSSecretsManagerSecretProviderDiscoveryConfig struct {
	UserID       string
	workspaceARN string
}

func (a AMPAWSSecretsManagerSecretProviderDiscoveryConfig) Name() string {
	return "aws_secrets_manager"
}

func (a AMPAWSSecretsManagerSecretProviderDiscoveryConfig) NewSecretsProvider(options secrets.SecretProviderOptions) (secrets.SecretsProvider, error) {
	secretsManagerProvider := NewAWSSecretsManagerProvider(options)
	userComponents := strings.Split(a.UserID, "_")
	if len(userComponents) != 2 {
		options.Logger.Info("user id is not in the correct format", "user id", a.UserID)
		return secretsManagerProvider, nil
	}
	account := userComponents[0]
	workspaceID := userComponents[1]
	region := os.Getenv("AWS_REGION")
	partition := os.Getenv("AWS_PARTITION")
	a.workspaceARN = fmt.Sprintf("arn:%s:aps:%s:%s:workspace/%s", partition, region, account, workspaceID)
	secretsManagerProvider.RoundTripper = newConfusedDeputyRoundTripper(a.workspaceARN, options.Logger)
	return secretsManagerProvider, nil
}

type confusedDeputyRoundTripper struct {
	workspaceARN arn.ARN
	rt           http.RoundTripper
	logger       *slog.Logger
}

func (rt *confusedDeputyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-amz-source-account", rt.workspaceARN.AccountID)
	req.Header.Set("x-amz-source-arn", rt.workspaceARN.String())
	rt.logger.Debug("round tripper called", "account id", rt.workspaceARN.AccountID, "arn", rt.workspaceARN.String())
	return rt.rt.RoundTrip(req)
}

func newConfusedDeputyRoundTripper(workspaceARN string, logger *slog.Logger) RoundTripperFn {
	parsedARN, err := arn.Parse(workspaceARN)
	return func(rt http.RoundTripper) (http.RoundTripper, error) {
		if workspaceARN == "" {
			return rt, nil
		}

		if err != nil {
			return nil, fmt.Errorf("%s is not a valid arn", workspaceARN)
		}
		return &confusedDeputyRoundTripper{parsedARN, rt, logger}, nil
	}
}
