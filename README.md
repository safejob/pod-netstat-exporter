docker build -t registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20250707 .

docker push registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20250707

docker tag registry.cn-hangzhou.aliyuncs.com/keruyun/pod-netstat-exporter:20250707 mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20250707
docker push mw-registry-registry.cn-shanghai.cr.aliyuncs.com/mwprod/pod-netstat-exporter:20250707


---
kubegray rollout restart daemonset -n monitoring pod-netstat-exporter
kubeprod rollout restart daemonset -n monitoring pod-netstat-exporter
kubenprod rollout restart daemonset -n monitoring pod-netstat-exporter
