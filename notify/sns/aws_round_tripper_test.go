package sns

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/alertmanager/config"
	commoncfg "github.com/prometheus/common/config"
)

func TestRoundTripperWithArnNotConfigured(t *testing.T) {
	var testCases = []struct {
		name                 string
		snsConfig            config.SNSConfig
		expectedHeaders      map[string]string
		deniedHeaders        []string
		expectedErrorMessage string
	}{
		{
			name: "Workspace invalid Arn configured",
			snsConfig: config.SNSConfig{
				WorkspaceArn: "arn:--Invalid",
			},
			expectedHeaders:      map[string]string{},
			deniedHeaders:        []string{},
			expectedErrorMessage: "arn:--Invalid is not a valid arn",
		},
		{
			name:            "Workspace Arn not configured",
			snsConfig:       config.SNSConfig{},
			expectedHeaders: map[string]string{},
			deniedHeaders: []string{
				"x-amz-source-account",
				"x-amz-source-arn",
				"x-amz-delegation-source-arn",
				"x-amz-delegation-source-account",
			},
		},
		{
			name: "Workspace Arn configured",
			snsConfig: config.SNSConfig{
				WorkspaceArn: "arn:aws:aps:us-west-2:948363459592:workspace/ws-de4908b6-950e-4c4c-9e49-ec68169bc4c7",
			},
			expectedHeaders: map[string]string{
				"x-amz-delegation-source-account": "948363459592",
				"x-amz-delegation-source-arn":     "arn:aws:aps:us-west-2:948363459592:workspace/ws-de4908b6-950e-4c4c-9e49-ec68169bc4c7",
			},
			deniedHeaders: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testServer := newTestServer(func(w http.ResponseWriter, r *http.Request) {
				for _, name := range tc.deniedHeaders {
					if _, ok := r.Header[name]; ok {
						t.Fatalf("Header %s should not be set", name)
					}
				}

				for key, value := range tc.expectedHeaders {
					if r.Header.Get(key) != value {
						t.Fatalf("The received Headers (%s) does not contain all expected headers (%s).", r.Header, tc.expectedHeaders)
						return
					}
				}
			})

			defer testServer.Close()

			client, err := commoncfg.NewClientFromConfig(commoncfg.HTTPClientConfig{}, "test")

			if err != nil && err.Error() != tc.expectedErrorMessage {
				t.Fatal(err.Error())
			}

			client.Transport, err = newConfusedDeputyRoundTripper(&tc.snsConfig, client.Transport)

			if err != nil && err.Error() != tc.expectedErrorMessage {
				t.Fatal(err.Error())
			}

			_, err = client.Get(testServer.URL)

			if err != nil && err.Error() != tc.expectedErrorMessage {
				t.Fatal(err.Error())
			}
		})
	}
}

func newTestServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	testServer.Start()
	return testServer
}
