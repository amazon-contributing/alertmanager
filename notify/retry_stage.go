// Copyright The Prometheus Authors
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
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/alertobserver"
	"github.com/prometheus/alertmanager/eventrecorder"
)

// RetryStage notifies via passed integration with exponential backoff until it
// succeeds. It aborts if the context is canceled or timed out.
type RetryStage struct {
	integration     Integration
	groupName       string
	metrics         *Metrics
	labelValues     []string
	recorder        eventrecorder.Recorder
	alertLCObserver alertobserver.LifeCycleObserver
}

// NewRetryStage returns a new instance of a RetryStage.
func NewRetryStage(i Integration, groupName string, metrics *Metrics, recorder eventrecorder.Recorder, o alertobserver.LifeCycleObserver) *RetryStage {
	labelValues := []string{i.Name()}

	if metrics.ff.EnableReceiverNamesInMetrics() {
		labelValues = append(labelValues, i.receiverName)
	}

	return &RetryStage{
		integration:     i,
		groupName:       groupName,
		metrics:         metrics,
		labelValues:     labelValues,
		recorder:        recorder,
		alertLCObserver: o,
	}
}

func (r RetryStage) Exec(ctx context.Context, l *slog.Logger, alerts ...*alert.Alert) (context.Context, []*alert.Alert, error) {
	r.metrics.numNotifications.WithLabelValues(r.labelValues...).Inc()

	ctx, span := tracer.Start(ctx, "notify.RetryStage.Exec",
		trace.WithAttributes(attribute.String("alerting.group.name", r.groupName)),
		trace.WithAttributes(attribute.String("alerting.integration.name", r.integration.name)),
		trace.WithAttributes(attribute.StringSlice("alerting.label.values", r.labelValues)),
		trace.WithAttributes(attribute.Int("alerting.alerts.count", len(alerts))),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	ctx, alerts, sent, err := r.exec(ctx, l, alerts...)

	failureReason := DefaultReason.String()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		var e *ErrorWithReason
		if errors.As(err, &e) {
			failureReason = e.Reason.String()
		}
		r.metrics.numTotalFailedNotifications.WithLabelValues(append(r.labelValues, failureReason)...).Inc()
		if r.alertLCObserver != nil {
			m := alertobserver.AlertEventMeta{
				"ctx":         ctx,
				"integration": r.integration.Name(),
				"stageName":   "RetryStage",
			}
			r.alertLCObserver.Observe(alertobserver.EventAlertSendFailed, sent, m)
		}
	} else if r.alertLCObserver != nil {
		m := alertobserver.AlertEventMeta{
			"ctx":         ctx,
			"integration": r.integration.Name(),
			"stageName":   "RetryStage",
		}
		r.alertLCObserver.Observe(alertobserver.EventAlertSent, sent, m)
	}
	return ctx, alerts, err
}

func (r RetryStage) exec(ctx context.Context, l *slog.Logger, alerts ...*alert.Alert) (context.Context, []*alert.Alert, alert.AlertSlice, error) {
	var sent alert.AlertSlice

	// If we shouldn't send notifications for resolved alerts, but there are only
	// resolved alerts, report them all as successfully notified (we still want the
	// notification log to log them for the next run of DedupStage).
	if !r.integration.SendResolved() {
		firing, ok := FiringAlerts(ctx)
		if !ok {
			return ctx, nil, sent, errors.New("firing alerts missing")
		}
		if len(firing) == 0 {
			return ctx, alerts, sent, nil
		}
		for _, a := range alerts {
			if a.Status() != model.AlertResolved {
				sent = append(sent, a)
			}
		}
	} else {
		sent = alerts
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0 // Always retry.

	tick := backoff.NewTicker(b)
	defer tick.Stop()

	var (
		i    = 0
		iErr error
	)

	l = l.With("receiver", r.groupName, "integration", r.integration.String())
	if groupKey, ok := GroupKey(ctx); ok {
		l = l.With("aggrGroup", groupKey)
	}

	for {

		// Always check the context first to not notify again.
		select {
		case <-ctx.Done():
			if iErr == nil {
				iErr = ctx.Err()
				if errors.Is(iErr, context.Canceled) {
					iErr = NewErrorWithReason(ContextCanceledReason, iErr)
				} else if errors.Is(iErr, context.DeadlineExceeded) {
					iErr = NewErrorWithReason(ContextDeadlineExceededReason, iErr)
				}
			}

			if iErr != nil {
				return ctx, nil, sent, fmt.Errorf("%s/%s: notify retry canceled after %d attempts: %w", r.groupName, r.integration.String(), i, iErr)
			}
			return ctx, nil, sent, nil
		default:
		}

		select {
		case <-tick.C:
			now := time.Now()
			retry, err := r.integration.Notify(ctx, sent...)
			i++
			dur := time.Since(now)
			r.metrics.notificationLatencySeconds.WithLabelValues(r.labelValues...).Observe(dur.Seconds())
			r.metrics.numNotificationRequestsTotal.WithLabelValues(r.labelValues...).Inc()
			if err != nil {
				r.metrics.numNotificationRequestsFailedTotal.WithLabelValues(r.labelValues...).Inc()
				if !retry {
					return ctx, alerts, sent, fmt.Errorf("%s/%s: notify retry canceled due to unrecoverable error after %d attempts: %w", r.groupName, r.integration.String(), i, err)
				}
				if ctx.Err() == nil {
					if iErr == nil || err.Error() != iErr.Error() {
						// Log the error if the context isn't done and the error isn't the same as before.
						l.Warn("Notify attempt failed, will retry later", "attempts", i, "err", err)
					}
					// Save this error to be able to return the last seen error by an
					// integration upon context timeout.
					iErr = err
				}
			} else {
				l := l.With(
					"attempts", i,
					"duration", dur,
					"numAlerts", len(sent),
				)
				if i <= 1 {
					l.Debug("Notify success", "alerts", sent)
				} else {
					l.Info("Notify success")
				}

				r.recorder.RecordEvent(ctx, NewNotificationEvent(ctx, sent, r.integration))
				return ctx, alerts, sent, nil
			}
		case <-ctx.Done():
		}
	}
}
