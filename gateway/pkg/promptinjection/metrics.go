package promptinjection

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	promptRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prompt_injection_requests_total",
		Help: "Total number of prompt injection detection requests sent to the model.",
	}, []string{"host"})

	promptFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prompt_injection_failures_total",
		Help: "Number of prompt injection detections that failed before receiving a verdict.",
	}, []string{"host"})

	promptLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "prompt_injection_latency_ms_bucket",
		Help:    "Latency distribution for prompt injection detections (milliseconds).",
		Buckets: prometheus.ExponentialBuckets(10, 2, 8),
	}, []string{"host"})
)

func recordRequest(host string) {
	promptRequests.WithLabelValues(host).Inc()
}

func recordFailure(host string) {
	promptFailures.WithLabelValues(host).Inc()
}

func observeLatency(host string, d time.Duration) {
	promptLatency.WithLabelValues(host).Observe(float64(d.Milliseconds()))
}
