docker build -t registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114 .

docker push registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114

docker tag registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20251114 mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20251114
docker push mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20251114


---
kubegray rollout restart daemonset -n monitoring pod-netstat-exporter
kubeprod rollout restart daemonset -n monitoring pod-netstat-exporter
kubenprod rollout restart daemonset -n monitoring pod-netstat-exporter
