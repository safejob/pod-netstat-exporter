package docker

import (
	"bufio"
	"fmt"
	"io/ioutil"
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
// Modified to support both cgroup v1 and v2
func findCgroupMountpoint(hostMountPath, cgroupType string) (string, error) {
	output, err := ioutil.ReadFile(hostMountPath + "/proc/mounts")
	if err != nil {
		return "", err
	}

	// /proc/mounts has 6 fields per line, one mount per line, e.g.
	// cgroup v1: cgroup /sys/fs/cgroup/memory cgroup rw,relatime,memory 0 0
	// cgroup v2: cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, " ")
		if len(parts) == 6 {
			// Check for cgroup v2 (unified hierarchy)
			if parts[2] == "cgroup2" {
				logrus.Tracef("Found cgroup v2 mountpoint: %s", parts[1])
				return parts[1], nil
			}
			// Check for cgroup v1
			if parts[2] == "cgroup" {
				for _, opt := range strings.Split(parts[3], ",") {
					if opt == cgroupType {
						logrus.Tracef("Found cgroup v1 mountpoint for %s: %s", cgroupType, parts[1])
						return parts[1], nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("cgroup mountpoint not found for %s", cgroupType)
}

// Returns the relative path to the cgroup docker is running in.
// borrowed from docker/utils/utils.go
// modified to get the docker pid instead of using /proc/self
// Modified to support both cgroup v1 and v2
func getThisCgroup(hostMountPath, cgroupType string) (string, error) {
	output, err := ioutil.ReadFile(fmt.Sprintf(hostMountPath + "/proc/self/cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		// For cgroup v2, the format is: 0::/path
		if parts[0] == "0" && parts[1] == "" {
			logrus.Tracef("Found cgroup v2 path: %s", parts[2])
			return parts[2], nil
		}
		// For cgroup v1, any type used by docker should work
		if parts[1] == cgroupType {
			logrus.Tracef("Found cgroup v1 path for %s: %s", cgroupType, parts[2])
			return parts[2], nil
		}
	}
	return "", fmt.Errorf("cgroup '%s' not found in %s/proc/self/cgroup", cgroupType, hostMountPath)
}

// readPidFromFile reads the first PID from a cgroup tasks file or cgroup.procs file
func readPidFromFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, fmt.Errorf("No pid found in file %s", filename)
	}

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

// findCgroupFileRecursive recursively searches for cgroup files containing the container ID
func findCgroupFileRecursive(baseDir, containerId, filename string, maxDepth int) (string, error) {
	if maxDepth <= 0 {
		return "", fmt.Errorf("max depth reached")
	}

	// Try to find the file in current directory
	targetFile := filepath.Join(baseDir, filename)
	if _, err := os.Stat(targetFile); err == nil {
		// Check if the path contains the container ID
		if strings.Contains(baseDir, containerId) {
			return targetFile, nil
		}
	}

	// Read directory entries
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "", err
	}

	// Search subdirectories
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirName := entry.Name()
		// Skip if directory name doesn't contain relevant keywords
		if !strings.Contains(dirName, "kubepods") &&
			!strings.Contains(dirName, "pod") &&
			!strings.Contains(dirName, "cri-containerd") &&
			!strings.Contains(dirName, "docker") &&
			!strings.Contains(dirName, containerId) {
			continue
		}

		subDir := filepath.Join(baseDir, dirName)
		if result, err := findCgroupFileRecursive(subDir, containerId, filename, maxDepth-1); err == nil {
			return result, nil
		}
	}

	return "", fmt.Errorf("file not found")
}

// detectContainerRuntime tries to detect if we're dealing with containerd or docker
func detectContainerRuntime(hostMountPath string) string {
	// Check for containerd socket
	if _, err := ioutil.ReadFile(hostMountPath + "/run/containerd/containerd.sock"); err == nil {
		return "containerd"
	}

	// Check for docker socket
	if _, err := ioutil.ReadFile(hostMountPath + "/var/run/docker.sock"); err == nil {
		return "docker"
	}

	// Check systemd services
	output, err := ioutil.ReadFile(hostMountPath + "/proc/1/cgroup")
	if err == nil {
		if strings.Contains(string(output), "containerd") {
			return "containerd"
		}
		if strings.Contains(string(output), "docker") {
			return "docker"
		}
	}

	// Default to trying both
	return "unknown"
}

// Returns the first pid in a container.
// Modified to support both Docker and containerd
// Modified to support both cgroup v1 and v2
func getPidForContainer(hostMountPath, id string) (int, error) {
	logrus.Tracef("Looking for container %s PID", id)

	cgroupType := "memory"
	cgroupRoot, err := findCgroupMountpoint(hostMountPath, cgroupType)
	if err != nil {
		return 0, err
	}

	// Detect if we're using cgroup v2
	isCgroupV2 := false
	if output, err := ioutil.ReadFile(hostMountPath + "/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 && parts[2] == "cgroup2" && parts[1] == cgroupRoot {
				isCgroupV2 = true
				logrus.Tracef("Using cgroup v2")
				break
			}
		}
	}
	if !isCgroupV2 {
		logrus.Tracef("Using cgroup v1")
	}

	logrus.Tracef("Cgroup root: %s, version: v%s", cgroupRoot, map[bool]string{true: "2", false: "1"}[isCgroupV2])

	cgroupThis, err := getThisCgroup(hostMountPath, cgroupType)
	if err != nil {
		// For containerd, we can continue without cgroupThis
		logrus.Tracef("Could not get current cgroup, continuing: %v", err)
		cgroupThis = ""
	}

	runtime := detectContainerRuntime(hostMountPath)
	logrus.Tracef("Detected container runtime: %s", runtime)

	// Build comprehensive list of attempts for both containerd and docker
	var attempts []string

	// Cgroup v2 patterns (unified hierarchy)
	var cgroupV2Attempts []string
	if isCgroupV2 {
		// Use shorter container ID for better matching
		shortId := id
		if len(id) > 12 {
			shortId = id[:12]
		}

		cgroupV2Attempts = []string{
			// cgroup v2 uses cgroup.procs instead of tasks
			// Kubernetes with containerd - cgroup v2 patterns with full ID
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod*.slice", "cri-containerd-"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod*.slice", "cri-containerd-"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-pod*.slice", "cri-containerd-"+id+"*.scope", "cgroup.procs"),

			// Try with short ID
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod*.slice", "cri-containerd-"+shortId+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod*.slice", "cri-containerd-"+shortId+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-pod*.slice", "cri-containerd-"+shortId+"*.scope", "cgroup.procs"),

			// Without QoS slice prefix (some k8s versions)
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-pod*.slice", "cri-containerd-"+id+".scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-pod*.slice", "cri-containerd-"+shortId+".scope", "cgroup.procs"),

			// Generic wildcard patterns
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "*"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "*"+shortId+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "cri-containerd-"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "cri-containerd-"+shortId+"*.scope", "cgroup.procs"),

			// Nested pod slice patterns
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "*", "cri-containerd-"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "*", "cri-containerd-"+shortId+"*.scope", "cgroup.procs"),

			// System slice patterns
			filepath.Join(hostMountPath, cgroupRoot, "system.slice", "containerd.service", "*"+id+"*", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "system.slice", "containerd.service", "*"+shortId+"*", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "system.slice", "docker-"+id+"*.scope", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "system.slice", "docker-"+shortId+"*.scope", "cgroup.procs"),

			// Top-level kubepods without .slice suffix (some distributions)
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "besteffort", "pod*", "*"+id+"*", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "burstable", "pod*", "*"+id+"*", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "pod*", "*"+id+"*", "cgroup.procs"),
			filepath.Join(hostMountPath, cgroupRoot, "kubepods", "*", "pod*", "*"+id+"*", "cgroup.procs"),
		}
		attempts = append(attempts, cgroupV2Attempts...)
	}

	// Containerd patterns for cgroup v1 (try these first as they're more specific)
	containerdAttempts := []string{
		// Kubernetes with containerd - cgroup v1 patterns
		filepath.Join(hostMountPath, cgroupRoot, "kubepods", "besteffort", "pod*", "*"+id+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods", "burstable", "pod*", "*"+id+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods", "guaranteed", "pod*", "*"+id+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods", "pod*", "*"+id+"*", "tasks"),

		// systemd slice patterns for containerd
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod*.slice", "cri-containerd-"+id+"*.scope", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod*.slice", "cri-containerd-"+id+"*.scope", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-guaranteed.slice", "kubepods-guaranteed-pod*.slice", "cri-containerd-"+id+"*.scope", "tasks"),

		// More containerd systemd patterns
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "*", "cri-containerd-"+id+"*.scope", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "*", "cri-containerd-"+id+"*.scope", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "cri-containerd-"+id+"*.scope", "tasks"),

		// Alternative containerd patterns
		filepath.Join(hostMountPath, cgroupRoot, "system.slice", "containerd.service", "*", id+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "system.slice", "containerd.service", "tasks"),

		// Direct containerd patterns
		filepath.Join(hostMountPath, cgroupRoot, "containerd", "*"+id+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "containerd.service", "*"+id+"*", "tasks"),

		// Shortened container ID patterns (containerd sometimes uses shorter IDs)
		filepath.Join(hostMountPath, cgroupRoot, "kubepods", "*", "*"+id[:12]+"*", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "*", "*"+id[:12]+"*", "tasks"),
	}

	// Add relative paths if cgroupThis is available
	if cgroupThis != "" {
		containerdAttempts = append(containerdAttempts, []string{
			filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "kubepods", "besteffort", "pod*", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "kubepods", "burstable", "pod*", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "kubepods", "guaranteed", "pod*", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "containerd", "*"+id+"*", "tasks"),
			filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "*"+id+"*", "tasks"),
		}...)
	}

	// Docker patterns (original logic with wildcard adjustment)
	idWithWildcard := id + "*"
	dockerAttempts := []string{
		// Kubernetes with docker and CNI is even more different
		filepath.Join(hostMountPath, cgroupRoot, "..", "systemd", "kubepods", "*", "pod*", idWithWildcard, "tasks"),
		// Another flavor of containers location in recent kubernetes 1.11+
		filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "kubepods.slice", "kubepods-besteffort.slice", "*", "docker-"+idWithWildcard+".scope", "tasks"),
		// When runs inside of a container with recent kubernetes 1.11+
		filepath.Join(hostMountPath, cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "*", "docker-"+idWithWildcard+".scope", "tasks"),
		filepath.Join(hostMountPath, cgroupRoot, cgroupThis, idWithWildcard, "tasks"),
		// With more recent lxc versions use, cgroup will be in lxc/
		filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "lxc", idWithWildcard, "tasks"),
		// With more recent docker, cgroup will be in docker/
		filepath.Join(hostMountPath, cgroupRoot, cgroupThis, "docker", idWithWildcard, "tasks"),
		// Even more recent docker versions under systemd use docker-<id>.scope/
		filepath.Join(hostMountPath, cgroupRoot, "system.slice", "docker-"+idWithWildcard+".scope", "tasks"),
		// Even more recent docker versions under cgroup/systemd/docker/<id>/
		filepath.Join(hostMountPath, cgroupRoot, "..", "systemd", "docker", idWithWildcard, "tasks"),
	}

	// Prioritize attempts based on detected runtime
	if runtime == "containerd" {
		attempts = append(containerdAttempts, dockerAttempts...)
	} else {
		attempts = append(dockerAttempts, containerdAttempts...)
	}

	var filename string
	var matchedFiles []string

	for _, attempt := range attempts {
		filenames, err := filepath.Glob(attempt)
		if err != nil {
			logrus.Tracef("Error globbing %s: %v", attempt, err)
			continue
		}

		logrus.Tracef("Checking path: %s, found: %v", attempt, filenames)

		if len(filenames) > 1 {
			// If we have multiple matches, try to find the most specific one
			for _, fn := range filenames {
				if strings.Contains(fn, id) {
					matchedFiles = append(matchedFiles, fn)
				}
			}
			if len(matchedFiles) == 1 {
				filename = matchedFiles[0]
				break
			} else if len(matchedFiles) > 1 {
				// Still ambiguous, but take the first one
				logrus.Tracef("Multiple matches found, using first: %v", matchedFiles)
				filename = matchedFiles[0]
				break
			}
			// If no specific matches, continue to next attempt
		} else if len(filenames) == 1 {
			filename = filenames[0]
			break
		}
	}

	if filename == "" {
		// Last resort: try recursive search for cgroup v2
		if isCgroupV2 {
			logrus.Tracef("Attempting recursive search for container %s", id)
			shortId := id
			if len(id) > 12 {
				shortId = id[:12]
			}

			// Try with full ID first
			if result, err := findCgroupFileRecursive(filepath.Join(hostMountPath, cgroupRoot), id, "cgroup.procs", 5); err == nil {
				filename = result
				logrus.Tracef("Found via recursive search: %s", filename)
			} else if result, err := findCgroupFileRecursive(filepath.Join(hostMountPath, cgroupRoot), shortId, "cgroup.procs", 5); err == nil {
				// Try with short ID
				filename = result
				logrus.Tracef("Found via recursive search with short ID: %s", filename)
			}
		}
	}

	if filename == "" {
		return 0, fmt.Errorf("Unable to find container: %v (tried %d different cgroup patterns, cgroup version: v%s)", id, len(attempts), map[bool]string{true: "2", false: "1"}[isCgroupV2])
	}

	logrus.Tracef("Found cgroup file for container %s: %s", id, filename)
	return readPidFromFile(filename)
}
