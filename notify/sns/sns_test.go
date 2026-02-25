// Copyright 2021 Prometheus Team
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

package sns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/pkg/errors"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/sigv4"

	"github.com/stretchr/testify/require"
)

var logger = promslog.NewNopLogger()

func TestValidateMessage(t *testing.T) {
	var modifiedReasons []string

	invalidUtf8String := "\xc3\x28"
	err := validateMessage(logger, invalidUtf8String, &modifiedReasons)
	require.Equal(t, MessageNotValidUtf8, err.Error())
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Message: Error - not a valid UTF-8 encoded string", modifiedReasons[0])
	require.Equal(t, len(modifiedReasons), 1)

	emptyString := ""
	err = validateMessage(logger, emptyString, &modifiedReasons)
	require.Equal(t, MessageIsEmpty, err.Error())
	require.Equal(t, 2, len(modifiedReasons))
	require.Equal(t, "Message: Error - the message should not be empty", modifiedReasons[1])
}

func TestValidateAndTruncateSubject(t *testing.T) {
	var modifiedReasons []string
	notTruncate := make([]rune, 100)
	for i := range notTruncate {
		notTruncate[i] = 'e'
	}
	subject := validateAndTruncateSubject(logger, string(notTruncate), &modifiedReasons)
	require.Equal(t, string(notTruncate), subject)
	require.Equal(t, 100, utf8.RuneCountInString(string(subject)))

	modifiedReasons = nil
	willBeTruncate := make([]rune, 101)
	for i := range willBeTruncate {
		willBeTruncate[i] = 'e'
	}
	subject = validateAndTruncateSubject(logger, string(willBeTruncate), &modifiedReasons)
	require.Equal(t, string(notTruncate), subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - subject has been truncated from 101 characters because it exceeds the 100 character size limit", modifiedReasons[0])

	modifiedReasons = nil
	subjectWithNonAsciiAndExceedingSize := make([]rune, 102)
	subjectWithNonAsciiAndExceedingSize[0] = '\xc3'
	subjectWithNonAsciiAndExceedingSize[1] = '\x28'
	for i := 2; i < 102; i++ {
		subjectWithNonAsciiAndExceedingSize[i] = 'e'
	}

	subject = validateAndTruncateSubject(logger, string(subjectWithNonAsciiAndExceedingSize), &modifiedReasons)
	require.Equal(t, SubjectContainsIllegalChars, subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - contains control- or non-ASCII characters", modifiedReasons[0])

	modifiedReasons = nil
	nonAsciiString := "\xc3\x28"
	subject = validateAndTruncateSubject(logger, nonAsciiString, &modifiedReasons)
	require.Equal(t, SubjectContainsIllegalChars, subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - contains control- or non-ASCII characters", modifiedReasons[0])

	modifiedReasons = nil
	asciiControlString := "\a\b\t"
	subject = validateAndTruncateSubject(logger, asciiControlString, &modifiedReasons)
	require.Equal(t, SubjectContainsIllegalChars, subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - contains control- or non-ASCII characters", modifiedReasons[0])

	modifiedReasons = nil
	newLineString := "abc\ndef"
	subject = validateAndTruncateSubject(logger, newLineString, &modifiedReasons)
	require.Equal(t, SubjectContainsIllegalChars, subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - contains control- or non-ASCII characters", modifiedReasons[0])

	modifiedReasons = nil
	emptyString := ""
	subject = validateAndTruncateSubject(logger, emptyString, &modifiedReasons)
	require.Equal(t, SubjectEmpty, subject)
	require.Equal(t, 1, len(modifiedReasons))
	require.Equal(t, "Subject: Error - subject, if provided, must be non-empty", modifiedReasons[0])
}

func TestCreateAndValidateMessageAttributes(t *testing.T) {
	var modifiedReasons []string
	attributes := map[string]string{
		"Invalid0":        "",
		".Invalid1":       "123",
		"Invalid2.":       "123",
		"AWS.Invalid3":    "123",
		"Amazon.Invalid4": "123",
		"Invalid..5":      "123",
		"Valid0":          "123",
		"AmazonValid1":    "123",
		"valid.2":         "123",
		"valid-_3":        "123",
	}
	notifier, err := New(
		&config.SNSConfig{
			Attributes: attributes,
			HTTPConfig: &commoncfg.HTTPClientConfig{},
		},
		CreateTmpl(t),
		logger,
	)
	require.NoError(t, err)

	attributesAfterValidation := createAndValidateMessageAttributes(notifier, temlFunction(t), &modifiedReasons)

	require.Equal(t, 4, len(attributesAfterValidation))
	require.Equal(t, true, attributesAfterValidation["Valid0"] != nil)
	require.Equal(t, true, attributesAfterValidation["AmazonValid1"] != nil)
	require.Equal(t, true, attributesAfterValidation["valid.2"] != nil)
	require.Equal(t, true, attributesAfterValidation["valid-_3"] != nil)
	require.Equal(t, len(modifiedReasons), 1)
	require.Equal(t, "MessageAttribute: Error - 6 of message attributes have been removed because of invalid MessageAttributeKey or MessageAttributeValue", modifiedReasons[0])
}

func TestAddModifiedMessageAttributes(t *testing.T) {
	reasons := []string{"1", "2"}
	attributes := map[string]*sns.MessageAttributeValue{
		"truncated": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
	}

	addModifiedMessageAttributes(attributes, reasons)

	require.Equal(t, 2, len(attributes))
	require.Equal(t, "[\"1\",\"2\"]", *attributes["modified"].StringValue)
}

func TestTruncateMessageAttributesAndMessage_TotalSmallerThanSizeLimit(t *testing.T) {
	logger := promslog.NewNopLogger()

	reasons := []string{"1", "2"}
	sBuff := make([]byte, 30*1024)
	for i := range sBuff {
		sBuff[i] = byte(33)
	}

	attributes := map[string]*sns.MessageAttributeValue{
		"truncated":  &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
		"customized": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}

	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuff), false, &reasons)
	require.Equal(t, 2, len(truncateAttributes))
	require.Equal(t, len(string(sBuff)), len(truncatedMessage))
	require.Equal(t, 2, len(reasons))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) <= messageSizeLimitInBytes)
}

func TestTruncateMessageAttributesAndMessage_SMS(t *testing.T) {
	reasons := []string{"1", "2"}
	smsBuff := make([]rune, 1700)
	for i := range smsBuff {
		smsBuff[i] = 'e'
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"truncated":  &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
		"customized": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(smsBuff))},
	}
	_, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "123", attributes, string(smsBuff), false, &reasons)
	require.Equal(t, messageSizeLimitInCharactersForSMS, utf8.RuneCountInString(truncatedMessage))
}

func TestTruncateMessageAttributesAndMessage_MessageAttributesLargerThanSizeLimit(t *testing.T) {
	reasons := []string{"1", "2"}
	sBuff := make([]byte, 150*1024)
	for i := range sBuff {
		sBuff[i] = byte(33)
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"truncated":   &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
		"customized1": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
		"customized2": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}
	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuff), false, &reasons)
	require.Equal(t, 2, len(truncateAttributes))
	require.Equal(t, true, len(truncatedMessage) < 150*1024)
	require.Equal(t, "true", *truncateAttributes["truncated"].StringValue)
	require.Equal(t, 4, len(reasons))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) < messageSizeLimitInBytes)
}

func TestTruncateMessageAttributesAndMessage_messageHasBeenModified(t *testing.T) {
	// messageAttributes + message > 256KB, however the message has already been modified, truncate the messageAttributes and keep the original message
	reasons := []string{"1", "2"}
	sBuff := make([]byte, 150*1024)
	for i := range sBuff {
		sBuff[i] = byte(33)
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"truncated":   &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
		"customized1": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
		"customized2": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}
	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuff), true, &reasons)
	require.Equal(t, 1, len(truncateAttributes))
	require.Equal(t, 150*1024, len(truncatedMessage))
	require.Equal(t, 3, len(reasons))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) <= messageSizeLimitInBytes)

}

func TestTruncateMessageAttributesAndMessage_atLeast1ByteForMessage(t *testing.T) {
	//we still have rooms for reasons and at least 1 byte for message
	messageBuff := make([]byte, messageSizeLimitInBytes)
	for i := range messageBuff {
		messageBuff[i] = byte(33)
	}

	reservedMessageModifiedBytes, _ := getMessageSizeExceedReservedBytes(string(messageBuff))
	reasons := []string{"1", "2"}
	modifiedReasonBytes, _ := getModifiedReasonMessageAttributeSize(reasons)
	sBuff := make([]byte, messageSizeLimitInBytes-reservedMessageModifiedBytes-1-modifiedReasonBytes-len("customized1")-len("String"))
	for i := range sBuff {
		sBuff[i] = byte(33)
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"customized1": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}
	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuff), false, &reasons)
	require.Equal(t, 2, len(truncateAttributes))
	require.Equal(t, "true", *truncateAttributes["truncated"].StringValue)
	require.Equal(t, true, len(truncatedMessage) >= 1)
	require.Equal(t, 3, len(reasons))
	fmt.Println("message", len(truncatedMessage))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) <= messageSizeLimitInBytes)
}

func TestTruncateMessageAttributesAndMessage_truncateMessage(t *testing.T) {
	reasons := []string{"1", "2"}
	sBuff := make([]byte, 3*1024)
	for i := range sBuff {
		sBuff[i] = byte(33)
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"customized1": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}

	sBuffMessage := make([]byte, 256*1024)

	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuffMessage), false, &reasons)
	require.Equal(t, 2, len(truncateAttributes))
	require.Equal(t, "true", *truncateAttributes["truncated"].StringValue)
	require.Equal(t, true, len(truncatedMessage) >= 1)
	require.Equal(t, 3, len(reasons))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) <= messageSizeLimitInBytes)
}

func TestTruncateMessageAttributesAndMessage_exactSize(t *testing.T) {
	var reasons []string
	sBuff := make([]byte, 128*1024-len("String")-len("customized1"))
	for i := range sBuff {
		sBuff[i] = byte(33)
	}
	attributes := map[string]*sns.MessageAttributeValue{
		"customized1": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}

	sBuffMessage := make([]byte, 128*1024)

	truncateAttributes, truncatedMessage, _ := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuffMessage), false, &reasons)
	require.Equal(t, 1, len(truncateAttributes))
	require.Equal(t, true, truncateAttributes["truncated"] == nil)
	require.Equal(t, true, len(truncatedMessage) == 128*1024)
	require.Equal(t, 0, len(reasons))
	require.Equal(t, true, getTotalSizeInBytes(reasons, truncateAttributes, truncatedMessage) == 256*1024)
}

func TestTruncateMessageAttributesAndMessage_marshalFailure(t *testing.T) {
	storedMarshal := jsonMarshal
	jsonMarshal = fakemarshal
	defer restoremarshal(storedMarshal)

	reasons := []string{"1", "2"}
	sBuff := make([]byte, 30*1024)
	for i := range sBuff {
		sBuff[i] = byte(33)
	}

	attributes := map[string]*sns.MessageAttributeValue{
		"truncated":  &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String("true")},
		"customized": &sns.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(sBuff))},
	}

	_, _, err := truncateMessageAttributesAndMessage(logger, "", attributes, string(sBuff), false, &reasons)
	require.Equal(t, true, err != nil)
}

func TestCreatePublishInput_noErrors(t *testing.T) {
	var (
		ctx     = context.Background()
		temlErr error
	)
	attributes := map[string]string{
		"attribName1": "attribValue1",
		"attribName2": "attribValue2",
		"attribName3": "attribValue3",
	}
	notifier, err := New(
		&config.SNSConfig{
			Attributes:  attributes,
			HTTPConfig:  &commoncfg.HTTPClientConfig{},
			TopicARN:    "TestTopic",
			PhoneNumber: "TestPhone",
			TargetARN:   "TestTarget",
			Subject:     "TestSubject",
			Message:     "TestMessage",
		},
		CreateTmpl(t),
		logger,
	)
	require.NoError(t, err)

	publishInput, err := createPublishInput(ctx, notifier, temlFunction(t), &temlErr)

	require.Equal(t, "TestTopic", *publishInput.TopicArn)
	require.Equal(t, "TestPhone", *publishInput.PhoneNumber)
	require.Equal(t, "TestTarget", *publishInput.TargetArn)
	require.Equal(t, "TestSubject", *publishInput.Subject)
	require.Equal(t, "TestMessage", *publishInput.Message)

	_, hasModifiedAttrib := publishInput.MessageAttributes["modified"]
	require.False(t, hasModifiedAttrib)
}

func TestCreatePublishInput_subjectOmitted(t *testing.T) {
	var (
		ctx     = context.Background()
		temlErr error
	)
	attributes := map[string]string{
		"attribName1": "attribValue1",
		"attribName2": "attribValue2",
		"attribName3": "attribValue3",
	}
	notifier, err := New(
		&config.SNSConfig{
			Attributes:  attributes,
			HTTPConfig:  &commoncfg.HTTPClientConfig{},
			TopicARN:    "TestTopic",
			PhoneNumber: "TestPhone",
			TargetARN:   "TestTarget",
			Subject:     "",
			Message:     "TestMessage",
		},
		CreateTmpl(t),
		logger,
	)
	require.NoError(t, err)

	publishInput, err := createPublishInput(ctx, notifier, temlFunction(t), &temlErr)

	require.Equal(t, "TestTopic", *publishInput.TopicArn)
	require.Equal(t, "TestPhone", *publishInput.PhoneNumber)
	require.Equal(t, "TestTarget", *publishInput.TargetArn)
	require.Nil(t, publishInput.Subject)
	require.Equal(t, "TestMessage", *publishInput.Message)

	require.Nil(t, publishInput.MessageAttributes["modified"])
}

func TestCreatePublishInput_subjectEmpty(t *testing.T) {
	var (
		ctx     = context.Background()
		temlErr error
	)
	attributes := map[string]string{
		"attribName1": "attribValue1",
		"attribName2": "attribValue2",
		"attribName3": "attribValue3",
	}
	notifier, err := New(
		&config.SNSConfig{
			Attributes:  attributes,
			HTTPConfig:  &commoncfg.HTTPClientConfig{},
			TopicARN:    "TestTopic",
			PhoneNumber: "TestPhone",
			TargetARN:   "TestTarget",
			Subject:     "TestSubject",
			Message:     "TestMessage",
		},
		CreateTmpl(t),
		logger,
	)
	require.NoError(t, err)
	temlFunc := func(input string) string {
		if input == "TestSubject" {
			return ""
		}
		return input
	}

	publishInput, err := createPublishInput(ctx, notifier, temlFunc, &temlErr)

	require.Equal(t, "TestTopic", *publishInput.TopicArn)
	require.Equal(t, "TestPhone", *publishInput.PhoneNumber)
	require.Equal(t, "TestTarget", *publishInput.TargetArn)
	require.Equal(t, SubjectEmpty, *publishInput.Subject)
	require.Equal(t, "TestMessage", *publishInput.Message)

	require.Contains(t, *publishInput.MessageAttributes["modified"].StringValue, SubjectEmpty)
}

func TestNotify_errorInTemplate(t *testing.T) {
	for _, tc := range []struct {
		title     string
		errorMsg  string
		updateCfg func(*config.SNSConfig)
	}{
		{
			title:    "with invalid Attribute template",
			errorMsg: "execute 'attributes' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.Attributes = map[string]string{
					"attribName1": "{{ template \"unknown_template\" . }}",
				}
			},
		},
		{
			title:    "with invalid TopicArn template",
			errorMsg: "execute 'topic_arn' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.TopicARN = "{{ template \"unknown_template\" . }}"
			},
		},
		{
			title:    "with invalid PhoneNumber template",
			errorMsg: "execute 'phone_number' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.PhoneNumber = "{{ template \"unknown_template\" . }}"
			},
		},
		{
			title:    "with invalid Message template",
			errorMsg: "execute 'message' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.Message = "{{ template \"unknown_template\" . }}"
			},
		},
		{
			title:    "with  invalid Subject template",
			errorMsg: "execute 'subject' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.Subject = "{{ template \"unknown_template\" . }}"
			},
		},
		{
			title:    "with  invalid APIUrl template",
			errorMsg: "execute 'api_url' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.APIUrl = "{{ template \"unknown_template\" . }}"
			},
		},
		{
			title:    "with  invalid TargetARN template",
			errorMsg: "execute 'target_arn' template",
			updateCfg: func(cfg *config.SNSConfig) {
				cfg.TargetARN = "{{ template \"unknown_template\" . }}"
			},
		},
	} {
		tc := tc
		t.Run(tc.title, func(t *testing.T) {
			snsCfg := &config.SNSConfig{
				HTTPConfig: &commoncfg.HTTPClientConfig{},
				TopicARN:   "TestTopic",
				Sigv4: sigv4.SigV4Config{
					Region: "us-west-2",
				},
			}
			if tc.updateCfg != nil {
				tc.updateCfg(snsCfg)
			}
			notifier, err := New(
				snsCfg,
				CreateTmpl(t),
				logger,
			)
			require.NoError(t, err)
			var alerts []*types.Alert
			_, err = notifier.Notify(context.Background(), alerts...)
			require.Error(t, err)
			require.Equal(t, true, err != nil)
			require.True(t, strings.Contains(err.Error(), "template \"unknown_template\" not defined"))
			require.True(t, strings.Contains(err.Error(), tc.errorMsg))
		})
	}
}

func getTotalSizeInBytes(modifiedReasons []string, attributes map[string]*sns.MessageAttributeValue, message string) int {
	attributesSize := 0
	for k, v := range attributes {
		attributesSize += len(k) + len(*v.DataType) + len(*v.StringValue)
	}

	modifiedReasonsSize := 0
	if len(modifiedReasons) > 0 {
		jsonString, _ := json.Marshal(modifiedReasons)
		modifiedReasonsSize = len("String.Array") + len("modified") + len(string(jsonString))
	}
	return modifiedReasonsSize + attributesSize + len(message)
}

// CreateTmpl returns a ready-to-use template.
func CreateTmpl(t *testing.T) *template.Template {
	tmpl, err := template.FromGlobs([]string{})
	require.NoError(t, err)
	tmpl.ExternalURL, _ = url.Parse("http://am")
	return tmpl
}

// CreateTmpl returns a ready-to-use template.
func temlFunction(t *testing.T) func(string) string {
	return func(input string) string {
		return input
	}
}

func fakemarshal(v interface{}) ([]byte, error) {
	return []byte{}, errors.New("Marshalling failed")
}

func restoremarshal(replace func(v interface{}) ([]byte, error)) {
	jsonMarshal = replace
}
