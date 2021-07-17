package process

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"
)

const (
	runProcessName         = "run-process"
	outputFileFlags        = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	procfsPropagationFlags = syscall.MS_PRIVATE | syscall.MS_REC
	procfsMountFlags       = syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV
)

type RunSpec struct {
	// Command to launch after setting up namespaces
	Command string `json:"command"`
	// Arguments to pass to the command
	Args []string `json:"args"`
	// Limits to apply via cgroups
	Limits ResourceLimits `json:"limits"`
	// Root directory to create cgroups (probably /sys/fs/cgroup)
	CgroupRootDir string `json:"cgroup_root_dir"`
	// File to store stdout
	OutputFile string `json:"output_file"`
	// File to store stderr
	ErrorFile string `json:"error_file`
	// Seconds to wait after SIGTERM before sending SIGKILL
	KillTimeoutSeconds int `json:"kill_timeout_secs"`
	// Testing use only
	doNotMountProc bool
}

type shim struct {
	spec        RunSpec
	cmd         *exec.Cmd
	stdout      *os.File
	stderr      *os.File
	cgroup      *Cgroup
	procMounted bool
	doneCh      chan struct{} // memory barrier for exitErr, exitCode
	exitErr     error
	exitCode    int
}

// Reexec must be called before execution of main program code
// by any package planning to run the command returned by
// ShimCommand() below.
func Reexec() {
	if os.Args[0] == runProcessName {
		os.Exit(runProcessMain())
	}
}

// ShimCommand returns a *exec.Cmd to launch the shim, based on the
// argument RunSpec. The process launched by this Cmd will be in new
// PID, mount, and network namespaces. The process specified in the
// RunSpec will be launched as a child of this process after setting up
// the namespaces, cgroups, and so on.
//
// Note: you must call Reexec() before running main program code if
//       you plan to use the command returned by this function.
func ShimCommand(spec RunSpec) (*exec.Cmd, error) {
	input, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}

	return &exec.Cmd{
		Path:   "/proc/self/exe",
		Args:   []string{runProcessName, string(input)},
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGKILL,
			Cloneflags: syscall.CLONE_NEWPID |
				syscall.CLONE_NEWNET |
				syscall.CLONE_NEWNS,
		},
	}, nil
}

func sigHandler(sigChan chan os.Signal, shim *shim) {
	for {
		sig, ok := <-sigChan
		if !ok {
			return
		}

		if err := shim.Stop(); err != nil {
			logrus.Warnf("error shutting down on %v: %v", sig, err)
		}
	}
}

// runProcessMain is the entry point for the shim process
func runProcessMain() int {
	spec := RunSpec{}
	if err := json.Unmarshal([]byte(os.Args[1]), &spec); err != nil {
		logrus.Fatalf("Error unmarshaling RunSpec %q: %v", os.Args[1], err)
	}

	shim, err := newShim(spec)
	if err != nil {
		logrus.Fatalf("Error creating shim: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	go sigHandler(sigChan, shim)

	code, err := shim.Wait()
	if err != nil {
		logrus.Infof("Process exited with error: %v", err)
	}

	if err := shim.Cleanup(); err != nil {
		logrus.Warnf("Error during shim cleanup: %v", err)
	}
	return code
}

// newShim is meant to be called from within the shim process. It
// sets up and launches the process, including cgroups and namespaces.
// If a nil error is returned, the caller is responsible for calling
// Cleanup().
func newShim(spec RunSpec) (*shim, error) {
	shim := &shim{
		spec:   spec,
		doneCh: make(chan struct{}),
	}

	if err := shim.setup(spec); err != nil {
		if cleanupErr := shim.Cleanup(); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
		return nil, err
	}
	return shim, nil
}

// setup performs the initial setup of the shim.
func (s *shim) setup(spec RunSpec) error {
	var err error
	if s.stdout, err = os.OpenFile(spec.OutputFile, outputFileFlags, 0600); err != nil {
		return err
	}

	if s.stderr, err = os.OpenFile(spec.ErrorFile, outputFileFlags, 0600); err != nil {
		return err
	}

	if s.cgroup, err = NewCgroup(CgroupOptions{
		Limits:  spec.Limits,
		RootPID: os.Getpid(),
		RootDir: spec.CgroupRootDir,
	}); err != nil {
		return err
	}

	if !spec.doNotMountProc {
		if err := s.mountProc(); err != nil {
			return err
		}
	}

	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
	return s.start(cmd)
}

// Wait blocks until the child process exits, returning its return
// code and error.
func (s *shim) Wait() (int, error) {
	<-s.doneCh
	return s.exitCode, s.exitErr
}

// Stop stops the process by first sending a SIGTERM and waiting for
// up to s.spec.KillTimeoutSeconds. If the process has not exited, then
// a SIGKILL is sent. Finally, Stop waits for up to 1 second for the
// process to exit before returning an error.
func (s *shim) Stop() error {
	if !s.running() {
		return nil
	}

	// Send a SIGTERM
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	// Wait for the process to exit, SIGKILL if it doesn't.
	select {
	case <-s.doneCh:
		return nil
	case <-time.After(time.Second * time.Duration(s.spec.KillTimeoutSeconds)):
	}

	if err := s.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		return err
	}

	// Give the process 1 second to exit, error if it doesn't.
	select {
	case <-s.doneCh:
	case <-time.After(time.Second):
		return fmt.Errorf("process did not respond to SIGKILL")
	}
	return nil
}

// Cleanup stops the process if necessary and releases resources
// created by the Shim.
func (s *shim) Cleanup() error {
	var result error
	if s.cmd != nil {
		if err := s.Stop(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.stdout != nil {
		if err := s.stdout.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.stderr != nil {
		if err := s.stderr.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.cgroup != nil {
		if err := s.cgroup.Cleanup(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if err := s.unmountProc(); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

// start runs the target background, closing doneCh when it exits.
func (s *shim) start(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting process: %v", err)
	}
	s.cmd = cmd

	go func() {
		defer close(s.doneCh)
		s.exitErr = cmd.Wait()
		s.exitCode = cmd.ProcessState.ExitCode()
	}()

	return nil
}

// running returns true if the child process is currently running.
func (s *shim) running() bool {
	select {
	case <-s.doneCh:
		return false
	default:
		return true
	}
}

// mountProc first changes the propagation type for /proc to be
// private to avoid polluting the parent namespace, then mounts
// a new procfs over /proc.
func (s *shim) mountProc() error {
	if s.procMounted {
		return nil
	}

	// Change propagation type to private
	err := syscall.Mount("", "/proc", "", procfsPropagationFlags, "")
	if err != nil {
		return err
	}
	// Mount procfs over /proc
	err = syscall.Mount("proc", "/proc", "proc", procfsMountFlags, "")
	if err == nil {
		s.procMounted = true
	}
	return err
}

// unmountProc unmounts the procfs at /proc mounted by mountProc().
func (s *shim) unmountProc() error {
	if !s.procMounted {
		return nil
	}

	err := syscall.Unmount("/proc", 0)
	if err == nil {
		// There could be an error because /proc is already
		// not mounted, but we'll ignore that possibility.
		s.procMounted = false
	}
	return err
}
