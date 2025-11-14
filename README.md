docker build -t registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114 .

docker push registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114

docker tag registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114 mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20251114
docker push mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20251114


---
kubegray rollout restart daemonset -n monitoring pod-netstat-exporter
kubeprod rollout restart daemonset -n monitoring pod-netstat-exporter
kubenprod rollout restart daemonset -n monitoring pod-netstat-exporter



注意  
```go
func (pm *PodManager) shouldTrackPod(pod *core_v1.Pod) bool {
    // 检查是否是当前节点的 Pod
    if pod.Spec.NodeName != pm.nodeName {
        return false
    }

    // 检查是否使用 hostNetwork
    if pod.Spec.HostNetwork {
        return false  // ← 这里是问题所在!
    }
    
    // ... 其他检查
}
```
不会采集hostNetwork: true的容器
