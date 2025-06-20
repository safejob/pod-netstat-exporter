package docker

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// ContainerToPID finds the PID of the given container
func ContainerToPID(hostMountPath, container string) (int, error) {
	raw := strings.Replace(container, "containerd://", "", 1)
	return getPidForContainer(hostMountPath, raw)
}

// Everything below this point is modified from
// https://github.com/vishvananda/netns
// which according to the comments was mostly borrowed from
// the docker source code anyway
///////////////////////////////////////////////////////////////////////

// borrowed from docker/utils/utils.go
func findCgroupMountpoint(hostMountPath, cgroupType string) (string, error) {
	file, err := os.Open(hostMountPath + "/proc/mounts")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line) // 使用 Fields 替代 Split，更高效
		if len(parts) >= 4 && parts[2] == "cgroup" {
			opts := strings.Split(parts[3], ",")
			for _, opt := range opts {
				if opt == cgroupType {
					return parts[1], nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("cgroup mountpoint not found for %s", cgroupType)
}

// Returns the relative path to the cgroup docker is running in.
// borrowed from docker/utils/utils.go
// modified to get the docker pid instead of using /proc/self
func getThisCgroup(hostMountPath, cgroupType string) (string, error) {
	file, err := os.Open(hostMountPath + "/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3) // 限制分割数量
		if len(parts) >= 3 && parts[1] == cgroupType {
			return parts[2], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("cgroup '%s' not found in %s/proc/self/cgroup", cgroupType, hostMountPath)
}

// readPidFromFile reads the first PID from a cgroup tasks file
func readPidFromFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		pidStr := strings.TrimSpace(scanner.Text())
		if pidStr == "" {
			return 0, fmt.Errorf("No pid found in file %s", filename)
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return 0, fmt.Errorf("Invalid pid '%s': %s", pidStr, err)
		}
		return pid, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("No pid found in file %s", filename)
}

// detectContainerRuntime tries to detect if we're dealing with containerd or docker
func detectContainerRuntime(hostMountPath string) string {
	// 只检查文件是否存在，不读取内容
	if _, err := os.Stat(hostMountPath + "/run/containerd/containerd.sock"); err == nil {
		return "containerd"
	}

	if _, err := os.Stat(hostMountPath + "/var/run/docker.sock"); err == nil {
		return "docker"
	}

	return "unknown"
}

// buildAttemptPaths 构建尝试路径，避免在主函数中创建大量字符串
func buildAttemptPaths(hostMountPath, cgroupRoot, cgroupThis, id string, runtime string) []string {
	// 预分配合理大小的切片
	attempts := make([]string, 0, 20)

	// 只构建必要的路径，根据运行时类型优化
	if runtime == "containerd" || runtime == "unknown" {
		// Containerd patterns - 只包含最常见的模式
		attempts = append(attempts,
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "besteffort", "pod*", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "burstable", "pod*", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "*", "cri-containerd-"+id+"*.scope", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "*", "cri-containerd-"+id+"*.scope", "tasks"),
		)

		// 只在 cgroupThis 不为空时添加相对路径
		if cgroupThis != "" {
			attempts = append(attempts,
				filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "kubepods", "*", "*"+id+"*", "tasks"),
				filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "*"+id+"*", "tasks"),
			)
		}
	}

	if runtime == "docker" || runtime == "unknown" {
		// Docker patterns
		idWithWildcard := id + "*"
		attempts = append(attempts,
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "*", "docker-"+idWithWildcard+".scope", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, "system.slice", "docker-"+idWithWildcard+".scope", "tasks"),
		)

		if cgroupThis != "" {
			attempts = append(attempts,
				filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "docker", idWithWildcard, "tasks"),
				filepath.Join(hostMountPath, cgroupRoot, cgroupThis, idWithWildcard, "tasks"),
			)
		}
	}

	return attempts
}

// findMatchingFile 查找匹配的文件，优化 glob 操作
func findMatchingFile(attempts []string, id string) (string, error) {
	for _, attempt := range attempts {
		// 限制 glob 结果数量，避免内存爆炸
		matches, err := filepath.Glob(attempt)
		if err != nil {
			logrus.Tracef("Error globbing %s: %v", attempt, err)
			continue
		}

		// 限制处理的匹配数量
		if len(matches) > 10 {
			logrus.Tracef("Too many matches for %s, skipping", attempt)
			continue
		}

		logrus.Tracef("Checking path: %s, found %d matches", attempt, len(matches))

		if len(matches) == 1 {
			return matches[0], nil
		} else if len(matches) > 1 {
			// 寻找最精确的匹配
			for _, match := range matches {
				if strings.Contains(match, id) {
					return match, nil
				}
			}
			// 如果没有精确匹配，使用第一个
			return matches[0], nil
		}
	}

	return "", fmt.Errorf("no matching cgroup file found")
}

// Returns the first pid in a container.
// Modified to support both Docker and containerd with memory optimization
func getPidForContainer(hostMountPath, id string) (int, error) {
	logrus.Tracef("Looking for container %s PID", id)

	cgroupType := "memory"
	cgroupRoot, err := findCgroupMountpoint(hostMountPath, cgroupType)
	if err != nil {
		return 0, err
	}

	cgroupThis, err := getThisCgroup(hostMountPath, cgroupType)
	if err != nil {
		logrus.Tracef("Could not get current cgroup, continuing: %v", err)
		cgroupThis = ""
	}

	runtime := detectContainerRuntime(hostMountPath)
	logrus.Tracef("Detected container runtime: %s", runtime)

	// 构建尝试路径
	attempts := buildAttemptPaths(hostMountPath, cgroupRoot, cgroupThis, id, runtime)

	// 查找匹配的文件
	filename, err := findMatchingFile(attempts, id)
	if err != nil {
		return 0, fmt.Errorf("Unable to find container: %v", id)
	}

	logrus.Tracef("Found cgroup file for container %s: %s", id, filename)
	return readPidFromFile(filename)
}
