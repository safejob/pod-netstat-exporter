package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	core_v1 "k8s.io/api/core/v1"

	"github.com/eegseth/pod-netstat-exporter/pkg/docker"
	"github.com/eegseth/pod-netstat-exporter/pkg/metrics"
	"github.com/eegseth/pod-netstat-exporter/pkg/netstat"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	_ "net/http/pprof"
)

type ops struct {
	LogLevel      string  `long:"log-level" env:"LOG_LEVEL" description:"Log level" default:"info"`
	RateLimit     float64 `long:"rate-limit" env:"RATE_LIMIT" description:"The number of /metrics requests served per second" default:"3"`
	BindAddr      string  `long:"bind-address" short:"p" env:"BIND_ADDRESS" default:":9657" description:"address for binding metrics listener"`
	HostMountPath string  `long:"host-mount-path" env:"HOST_MOUNT_PATH" default:"/host" description:"The path where the host filesystem is mounted"`
}

func setupLogging(logLevel string) {
	// Use log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Fatalf("Unknown log level %s: %v", logLevel, err)
	}
	logrus.SetLevel(level)

	// Set the log format to have a reasonable timestamp
	formatter := &logrus.TextFormatter{
		FullTimestamp: true,
	}
	logrus.SetFormatter(formatter)
}

func getPodNetstats(opts *ops, pod *core_v1.Pod) (*netstat.NetStats, error) {
	logrus.Tracef("Getting stats for pod %v", pod.Name)
	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, fmt.Errorf("No containers in pod")
	}
	container := pod.Status.ContainerStatuses[0].ContainerID
	pid, err := docker.ContainerToPID(opts.HostMountPath, container)
	if err != nil {
		return nil, fmt.Errorf("Error getting pid for container %v: %v", container, err)
	}
	logrus.Tracef("Container %v of pod %v has PID %v", container, pod.Name, pid)
	stats, err := netstat.GetStats(opts.HostMountPath, pid)
	return &stats, err
}

var podStatsPool = sync.Pool{
	New: func() interface{} {
		return make([]*metrics.PodStats, 0, 100)
	},
}

func allPodStats(opts *ops) ([]*metrics.PodStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	podStats := podStatsPool.Get().([]*metrics.PodStats)
	defer func() {
		// 清理切片中的指针引用
		for i := range podStats {
			podStats[i] = nil
		}
		podStats = podStats[:0]
		podStatsPool.Put(podStats)
	}()

	clientset, err := getK8sClient()
	if err != nil {
		panic(err.Error())
	}

	p, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return podStats, fmt.Errorf("Error getting pod list: %v", err)
	}

	// Actually fetch the per-pod statistics
	for _, pod := range p.Items {
		if pod.Spec.HostNetwork {
			logrus.Tracef("Pod %v has hostNetwork: true, cannot fetch per-pod network metrics", pod.Name)
			continue
		}

		stats, err := getPodNetstats(opts, &pod)
		if err != nil {
			logrus.Warnf("Could not get stats for pod %v: %v", pod.Name, err)
			continue
		}
		podStats = append(podStats, &metrics.PodStats{
			NetStats:  *stats,
			Name:      pod.Name,
			Namespace: pod.Namespace,
		})
	}

	return podStats, nil
}

func main() {

	opts := &ops{}
	parser := flags.NewParser(opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		// If the error was from the parser, then we can simply return
		// as Parse() prints the error already
		if _, ok := err.(*flags.Error); ok {
			os.Exit(1)
		}
		logrus.Fatalf("Error parsing flags: %v", err)
	}
	setupLogging(opts.LogLevel)

	srv := &http.Server{
		Addr: opts.BindAddr,
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})
	http.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})
	metricsLimiter := rate.NewLimiter(rate.Limit(opts.RateLimit), 5)
	http.HandleFunc("/metrics", func(rsp http.ResponseWriter, req *http.Request) {
		if metricsLimiter.Allow() == false {
			http.Error(rsp, http.StatusText(429), http.StatusTooManyRequests)
			return
		}

		stats, err := allPodStats(opts)
		if err != nil {
			logrus.Error(err)
			metrics.HTTPError(rsp, err)
			return
		}

		metrics.Handler(rsp, req, stats)
	})
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logrus.Errorf("Error serving HTTP at %v: %v", opts.BindAddr, err)
		}
	}()

	startMemoryMonitor()

	stopCh := make(chan struct{})
	defer close(stopCh)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	signal.Notify(sigterm, syscall.SIGINT)
	<-sigterm

	logrus.Info("Received SIGTERM or SIGINT. Shutting down.")
	srv.Shutdown(context.Background())

}

var (
	k8sClient kubernetes.Interface
	k8sOnce   sync.Once
)

func getK8sClient() (kubernetes.Interface, error) {
	var err error
	k8sOnce.Do(func() {
		config, configErr := rest.InClusterConfig()
		if configErr != nil {
			err = configErr
			return
		}
		k8sClient, err = kubernetes.NewForConfig(config)
	})
	return k8sClient, err
}

func startMemoryMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			runtime.GC() // 强制垃圾回收
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			logrus.Infof("Memory usage: Alloc=%d KB, TotalAlloc=%d KB, Sys=%d KB, NumGC=%d",
				m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)
		}
	}()
}
