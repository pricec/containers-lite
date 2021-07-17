package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	memoryFile    = "memory.limit_in_bytes"
	cpuPeriodFile = "cpu.cfs_period_us"
	cpuQuotaFile  = "cpu.cfs_quota_us"
	diskReadFile  = "blkio.throttle.read_bps_device"
	diskWriteFile = "blkio.throttle.write_bps_device"
)

type ResourceLimits struct {
	// Maximum memory in mebibytes
	MemoryInMiB int `json:"memory_in_mib"`
	// Maximum millicores (reservation) - 1000 millicores = 1 CPU core
	CPUMillicores int `json:"cpu_millicores"`
	// Maximum disk read speed in megabytes per second
	DiskReadMBPS int `json:"disk_read_mbps"`
	// Maximum disk write speed in megabytes per second
	DiskWriteMBPS int `json:"disk_write_mbps"`
	// Disk device to apply disk limits to (probably sda)
	DiskLimitDevice string `json:"disk_limit_device"`
}

// setMemory applies the memory limit to the memory cgroup at dir.
func (l ResourceLimits) setMemory(dir string) error {
	file := filepath.Join(dir, memoryFile)
	return setCgroupValue(file, l.MemoryInMiB*1024*1024)
}

// setCPU applies the CPU limit to the cpu cgroup at dir.
func (l ResourceLimits) setCPU(dir string) error {
	periodFile := filepath.Join(dir, cpuPeriodFile)
	quotaFile := filepath.Join(dir, cpuQuotaFile)
	if err := setCgroupValue(periodFile, 1000000); err != nil {
		return err
	}
	return setCgroupValue(quotaFile, l.CPUMillicores*1000)
}

// setDisk applies the disk limits to the blkio cgroup at dir
func (l ResourceLimits) setDisk(dir string) error {
	if l.DiskLimitDevice == "" {
		return fmt.Errorf("must specify non-empty block device to limit")
	}

	b, err := os.ReadFile(filepath.Join("/sys/block", l.DiskLimitDevice, "dev"))
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(string(b))

	readFile := filepath.Join(dir, diskReadFile)
	readValue := fmt.Sprintf("%s %d", addr, l.DiskReadMBPS*1000*1000)
	if err := setCgroupValue(readFile, readValue); err != nil {
		return err
	}

	writeFile := filepath.Join(dir, diskWriteFile)
	writeValue := fmt.Sprintf("%s %d", addr, l.DiskWriteMBPS*1000*1000)
	if err := setCgroupValue(writeFile, writeValue); err != nil {
		return err
	}
	return nil
}
