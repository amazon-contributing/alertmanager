package sns

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/prometheus/alertmanager/config"
)

type confusedDeputyRoundTripper struct {
	workspaceArn arn.ARN
	rt           http.RoundTripper
}

func (rt *confusedDeputyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-amz-delegation-source-account", rt.workspaceArn.AccountID)
	req.Header.Set("x-amz-delegation-source-arn", rt.workspaceArn.String())
	return rt.rt.RoundTrip(req)
}

// newConfusedDeputyRoundTripper adds confused deputy headers
func newConfusedDeputyRoundTripper(c *config.SNSConfig, rt http.RoundTripper) (http.RoundTripper, error) {
	if c.WorkspaceArn == "" {
		return rt, nil
	}

	arn, err := arn.Parse(c.WorkspaceArn)

	if err != nil {
		return nil, fmt.Errorf("%s is not a valid arn", c.WorkspaceArn)
	}
	return &confusedDeputyRoundTripper{arn, rt}, nil
}
