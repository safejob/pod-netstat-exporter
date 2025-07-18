package metrics

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/eegseth/pod-netstat-exporter/pkg/netstat"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
)

const (
	contentTypeHeader     = "Content-Type"
	contentEncodingHeader = "Content-Encoding"
)

// PodStats represents a pod and the metrics gathered for it
type PodStats struct {
	netstat.NetStats
	Name      string
	Namespace string
}

func s(s string) *string {
	return &s
}

func f(i int64) *float64 {
	f := float64(i)
	return &f
}

// generateMetrics creates the actual prometheus metrics from the raw pod stats
func generateMetrics(stats []*PodStats) []*dto.MetricFamily {
	timeMs := time.Now().Unix() * int64(time.Second/time.Millisecond)
	generateGaugeFamily := func(name, help string) *dto.MetricFamily {
		g := dto.MetricType_GAUGE
		return &dto.MetricFamily{
			Name:   &name,
			Help:   &help,
			Type:   &g,
			Metric: []*dto.Metric{},
		}
	}

	families := map[string]*dto.MetricFamily{}
	for _, podStat := range stats {
		for metricName, metricValue := range podStat.NetStats {
			family, ok := families["pod_netstat_"+metricName]
			if !ok {
				families["pod_netstat_"+metricName] = generateGaugeFamily(
					"pod_netstat_"+metricName,
					fmt.Sprintf("The per-pod value of the %v metric from /proc/net/(netstat|snmp|snmp6)", metricName),
				)
				family = families["pod_netstat_"+metricName]
			}
			family.Metric = append(family.Metric, &dto.Metric{
				Label: []*dto.LabelPair{
					{Name: s("namespace"), Value: &podStat.Namespace},
					{Name: s("pod"), Value: &podStat.Name},
					{Name: s("svc"), Value: getSvcName(podStat.Name)},
				},
				Gauge:       &dto.Gauge{Value: f(metricValue)},
				TimestampMs: &timeMs,
			})
		}
	}

	ret := []*dto.MetricFamily{}
	for _, metric := range families {
		ret = append(ret, metric)
	}
	return ret
}

func getSvcName(podName string) *string {
	if podName == "" {
		return nil
	}

	parts := strings.Split(podName, "-")
	if len(parts) < 2 {
		return &podName
	}

	lastPart := parts[len(parts)-1]

	// 规则1：StatefulSet - 最后一段长度 <= 2 且为数字
	if len(lastPart) <= 2 && isNumeric(lastPart) {
		result := strings.Join(parts[:len(parts)-1], "-")
		return &result
	}

	// 规则2：Deployment - 最后两段长度分别为 10/9 和 5
	if len(parts) >= 2 {
		secondLastPart := parts[len(parts)-2]
		if (len(secondLastPart) == 10 || len(secondLastPart) == 9) && len(lastPart) == 5 {
			result := strings.Join(parts[:len(parts)-2], "-")
			return &result
		}
	}

	// 规则3：DaemonSet - 最后一段长度为 5
	if len(lastPart) == 5 {
		result := strings.Join(parts[:len(parts)-1], "-")
		return &result
	}

	// 如果都不匹配，返回原始名称
	return &podName
}

// isNumeric 检查字符串是否为纯数字
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Handler returns metrics in response to an HTTP request
func Handler(rsp http.ResponseWriter, req *http.Request, stats []*PodStats) {
	logrus.Trace("Serving prometheus metrics")

	metrics := generateMetrics(stats)

	contentType := expfmt.Negotiate(req.Header)
	header := rsp.Header()
	header.Set(contentTypeHeader, string(contentType))
	w := io.Writer(rsp)
	enc := expfmt.NewEncoder(w, contentType)

	var lastErr error
	for _, mf := range metrics {
		if err := enc.Encode(mf); err != nil {
			lastErr = err
			HTTPError(rsp, err)
			return
		}
	}

	if lastErr != nil {
		HTTPError(rsp, lastErr)
	}
}

// HTTPError sends an error as an HTTP response
func HTTPError(rsp http.ResponseWriter, err error) {
	rsp.Header().Del(contentEncodingHeader)
	http.Error(
		rsp,
		"An error has occurred while serving metrics:\n\n"+err.Error(),
		http.StatusInternalServerError,
	)
}
