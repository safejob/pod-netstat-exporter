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
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	_ "net/http/pprof"
)

type ops struct {
	LogLevel      string  `long:"log-level" env:"LOG_LEVEL" description:"Log level" default:"info"`
	RateLimit     float64 `long:"rate-limit" env:"RATE_LIMIT" description:"The number of /metrics requests served per second" default:"3"`
	BindAddr      string  `long:"bind-address" short:"p" env:"BIND_ADDRESS" default:":9657" description:"address for binding metrics listener"`
	HostMountPath string  `long:"host-mount-path" env:"HOST_MOUNT_PATH" default:"/host" description:"The path where the host filesystem is mounted"` // 宿主机proc、sys、var目录在容器中的挂载目录
	NodeName      string  `long:"node-name" env:"NODE_NAME" description:"Current node name (should be set via downward API)"`
}

// PodManager 管理当前节点的 Pod 信息和统计数据
type PodManager struct {
	mu        sync.RWMutex
	pods      map[string]*core_v1.Pod // key: namespace/name
	stats     map[string]*metrics.PodStats
	opts      *ops
	clientset kubernetes.Interface
	stopCh    chan struct{}
	nodeName  string
}

func NewPodManager(opts *ops, clientset kubernetes.Interface) (*PodManager, error) {
	nodeName := opts.NodeName
	if nodeName == "" {
		// 尝试从环境变量获取节点名
		nodeName = os.Getenv("NODE_NAME") // k8s yaml中需要配置该环境变量
		if nodeName == "" {
			// 尝试从主机名获取
			hostname, err := os.Hostname()
			if err != nil {
				return nil, fmt.Errorf("failed to get node name: %v", err)
			}
			nodeName = hostname
		}
	}

	logrus.Infof("Monitoring pods on node: %s", nodeName)

	return &PodManager{
		pods:      make(map[string]*core_v1.Pod),
		stats:     make(map[string]*metrics.PodStats),
		opts:      opts,
		clientset: clientset,
		stopCh:    make(chan struct{}),
		nodeName:  nodeName,
	}, nil
}

func (pm *PodManager) Start() error {
	// 首先获取当前节点的现有 Pod 列表
	if err := pm.initialSync(); err != nil {
		return fmt.Errorf("initial sync failed: %v", err)
	}

	// 启动 watch goroutine
	go pm.watchPods()

	// 启动定期更新统计数据的 goroutine
	go pm.updateStatsLoop()

	return nil
}

func (pm *PodManager) Stop() {
	close(pm.stopCh)
}

func (pm *PodManager) initialSync() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 只获取当前节点的 Pod
	fieldSelector := fmt.Sprintf("spec.nodeName=%s", pm.nodeName)
	podList, err := pm.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, pod := range podList.Items {
		if pm.shouldTrackPod(&pod) {
			key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
			pm.pods[key] = pod.DeepCopy()
		}
	}

	logrus.Infof("Initial sync completed, tracking %d pods on node %s", len(pm.pods), pm.nodeName)
	return nil
}

func (pm *PodManager) shouldTrackPod(pod *core_v1.Pod) bool {
	// 检查是否是当前节点的 Pod
	if pod.Spec.NodeName != pm.nodeName {
		return false
	}

	// 检查是否使用 hostNetwork
	if pod.Spec.HostNetwork {
		return false
	}

	// 检查 Pod 状态
	if pod.Status.Phase != core_v1.PodRunning {
		return false
	}

	// 检查是否有容器状态
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}

	// 检查容器是否在运行
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			return true
		}
	}

	return false
}

func (pm *PodManager) watchPods() {
	for {
		select {
		case <-pm.stopCh:
			return
		default:
			if err := pm.runWatch(); err != nil {
				logrus.Errorf("Watch error: %v, retrying in 5 seconds", err)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (pm *PodManager) runWatch() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 只监控当前节点的 Pod
	fieldSelector := fmt.Sprintf("spec.nodeName=%s", pm.nodeName)
	listOptions := metav1.ListOptions{
		Watch:         true,
		FieldSelector: fieldSelector,
	}

	watcher, err := pm.clientset.CoreV1().Pods("").Watch(ctx, listOptions)
	if err != nil {
		return err
	}
	defer watcher.Stop()

	logrus.Infof("Started watching pod changes on node %s", pm.nodeName)

	for {
		select {
		case <-pm.stopCh:
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}

			pod, ok := event.Object.(*core_v1.Pod)
			if !ok {
				logrus.Warnf("Unexpected object type: %T", event.Object)
				continue
			}

			pm.handlePodEvent(event.Type, pod)
		}
	}
}

func (pm *PodManager) handlePodEvent(eventType watch.EventType, pod *core_v1.Pod) {
	key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	switch eventType {
	case watch.Added, watch.Modified:
		if pm.shouldTrackPod(pod) {
			pm.pods[key] = pod.DeepCopy()
			logrus.Tracef("Pod %s added/updated on node %s", key, pm.nodeName)
		} else {
			// 如果 Pod 不再符合条件，从跟踪列表中移除
			if _, exists := pm.pods[key]; exists {
				delete(pm.pods, key)
				delete(pm.stats, key)
				logrus.Tracef("Pod %s removed from tracking (no longer meets criteria)", key)
			}
		}
	case watch.Deleted:
		if _, exists := pm.pods[key]; exists {
			delete(pm.pods, key)
			delete(pm.stats, key)
			logrus.Tracef("Pod %s deleted from node %s", key, pm.nodeName)
		}
	}
}

func (pm *PodManager) updateStatsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			pm.updateAllStats()
		}
	}
}

func (pm *PodManager) updateAllStats() {
	pm.mu.RLock()
	pods := make([]*core_v1.Pod, 0, len(pm.pods))
	for _, pod := range pm.pods {
		pods = append(pods, pod)
	}
	pm.mu.RUnlock()

	if len(pods) == 0 {
		logrus.Trace("No pods to update stats for")
		return
	}

	var wg sync.WaitGroup
	statsChan := make(chan *metrics.PodStats, len(pods))

	// 并发获取统计数据，但限制并发数
	semaphore := make(chan struct{}, 10) // 最多10个并发

	for _, pod := range pods {
		wg.Add(1)
		go func(p *core_v1.Pod) {
			defer wg.Done()

			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			stats, err := pm.getPodNetstats(p)
			if err != nil {
				logrus.Warnf("Could not get stats for pod %s/%s: %v", p.Namespace, p.Name, err)
				return
			}

			statsChan <- &metrics.PodStats{
				NetStats:  *stats,
				Name:      p.Name,
				Namespace: p.Namespace,
			}
		}(pod)
	}

	go func() {
		wg.Wait()
		close(statsChan)
	}()

	// 收集结果并更新缓存
	newStats := make(map[string]*metrics.PodStats)
	for stat := range statsChan {
		key := fmt.Sprintf("%s/%s", stat.Namespace, stat.Name)
		newStats[key] = stat
	}

	pm.mu.Lock()
	pm.stats = newStats
	pm.mu.Unlock()

	logrus.Tracef("Updated stats for %d pods on node %s", len(newStats), pm.nodeName)
}

func (pm *PodManager) getPodNetstats(pod *core_v1.Pod) (*netstat.NetStats, error) {
	logrus.Tracef("Getting stats for pod %v", pod.Name)
	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, fmt.Errorf("No containers in pod")
	}

	// 找到第一个运行中的容器
	// todo 如果是多容器的Pod 存在第一个container不是主容器的情况
	var containerID string
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			containerID = containerStatus.ContainerID
			break
		}
	}

	if containerID == "" {
		return nil, fmt.Errorf("No running containers in pod")
	}

	pid, err := docker.ContainerToPID(pm.opts.HostMountPath, containerID)
	if err != nil {
		return nil, fmt.Errorf("Error getting pid for container %v: %v", containerID, err)
	}
	logrus.Tracef("Container %v of pod %v has PID %v", containerID, pod.Name, pid)
	stats, err := netstat.GetStats(pm.opts.HostMountPath, pid)
	return &stats, err
}

func (pm *PodManager) GetCurrentStats() []*metrics.PodStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make([]*metrics.PodStats, 0, len(pm.stats))
	for _, stat := range pm.stats {
		// 创建副本以避免并发访问问题
		statCopy := &metrics.PodStats{
			NetStats:  make(netstat.NetStats),
			Name:      stat.Name,
			Namespace: stat.Namespace,
		}
		for k, v := range stat.NetStats {
			statCopy.NetStats[k] = v
		}
		stats = append(stats, statCopy)
	}
	return stats
}

func (pm *PodManager) GetNodeName() string {
	return pm.nodeName
}

func setupLogging(logLevel string) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Fatalf("Unknown log level %s: %v", logLevel, err)
	}
	logrus.SetLevel(level)

	formatter := &logrus.TextFormatter{
		FullTimestamp: true,
	}
	logrus.SetFormatter(formatter)
}

func main() {
	opts := &ops{}
	parser := flags.NewParser(opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if _, ok := err.(*flags.Error); ok {
			os.Exit(1)
		}
		logrus.Fatalf("Error parsing flags: %v", err)
	}
	setupLogging(opts.LogLevel)

	clientset, err := getK8sClient()
	if err != nil {
		logrus.Fatalf("Failed to create k8s client: %v", err)
	}

	// 创建并启动 PodManager
	podManager, err := NewPodManager(opts, clientset)
	if err != nil {
		logrus.Fatalf("Failed to create pod manager: %v", err)
	}

	if err := podManager.Start(); err != nil {
		logrus.Fatalf("Failed to start pod manager: %v", err)
	}
	defer podManager.Stop()

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
		if !metricsLimiter.Allow() {
			http.Error(rsp, http.StatusText(429), http.StatusTooManyRequests)
			return
		}

		stats := podManager.GetCurrentStats()
		metrics.Handler(rsp, req, stats)
	})

	// 添加节点信息接口
	http.HandleFunc("/node", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Node: %s\n", podManager.GetNodeName())
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
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			logrus.Infof("Memory usage: Alloc=%d KB, TotalAlloc=%d KB, Sys=%d KB, NumGC=%d",
				m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)
		}
	}()
}
