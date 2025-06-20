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
func findCgroupMountpoint(hostMountPath, cgroupType string) (string, error) {
	output, err := ioutil.ReadFile(hostMountPath + "/proc/mounts")
	if err != nil {
		return "", err
	}

	// /proc/mounts has 6 fields per line, one mount per line, e.g.
	// cgroup /sys/fs/cgroup/devices cgroup rw,relatime,devices 0 0
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, " ")
		if len(parts) == 6 && parts[2] == "cgroup" {
			for _, opt := range strings.Split(parts[3], ",") {
				if opt == cgroupType {
					return parts[1], nil
				}
			}
		}
	}

	return "", fmt.Errorf("cgroup mountpoint not found for %s", cgroupType)
}

// Returns the relative path to the cgroup docker is running in.
// borrowed from docker/utils/utils.go
// modified to get the docker pid instead of using /proc/self
func getThisCgroup(hostMountPath, cgroupType string) (string, error) {
	output, err := ioutil.ReadFile(fmt.Sprintf(hostMountPath + "/proc/self/cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, ":")
		// any type used by docker should work
		if parts[1] == cgroupType {
			return parts[2], nil
		}
	}
	return "", fmt.Errorf("cgroup '%s' not found in %s/proc/%s/cgroup", cgroupType, hostMountPath, cgroupType)
}

// readPidFromFile reads the first PID from a cgroup tasks file
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
func getPidForContainer(hostMountPath, id string) (int, error) {
	logrus.Tracef("Looking for container %s PID", id)

	cgroupType := "memory"
	cgroupRoot, err := findCgroupMountpoint(hostMountPath, cgroupType)
	if err != nil {
		return 0, err
	}

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

	// Containerd patterns (try these first as they're more specific)
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
		return 0, fmt.Errorf("Unable to find container: %v (tried %d different cgroup patterns)", id, len(attempts))
	}

	logrus.Tracef("Found cgroup file for container %s: %s", id, filename)
	return readPidFromFile(filename)
}
