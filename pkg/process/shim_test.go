package process

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	multierror "github.com/hashicorp/go-multierror"
)

var (
	TestDisk       string
	TestCgroupRoot string
	TestLimits     ResourceLimits
)

func init() {
	Reexec()
	rand.Seed(time.Now().UnixNano())

	if TestDisk = os.Getenv("TEST_DISK"); TestDisk == "" {
		TestDisk = "sda"
	}
	if TestCgroupRoot = os.Getenv("TEST_CGROUP_ROOT"); TestCgroupRoot == "" {
		TestCgroupRoot = "/sys/fs/cgroup"
	}

	TestLimits = ResourceLimits{
		MemoryInMiB:     100,
		CPUMillicores:   300,
		DiskReadMBPS:    100,
		DiskWriteMBPS:   100,
		DiskLimitDevice: TestDisk,
	}
}

// TestSignaller is meant to help with a common problem encountered
// when testing the shim, namely that without complex IPC, it is
// difficult to know when the shim has set itself up and launched
// the process in the test case. We could just put the current goroutine
// to sleep for a bit, but how long is long enough? To help handle this,
// TestSignaller creates a temporary file and sets up an fsnotify watch
// on it. The caller is meant to write the file in a command or script to
// announce to the test that the shim's child has been launched.
type TestSignaller struct {
	watcher  *fsnotify.Watcher
	fileName string
}

func NewTestSignaller() (*TestSignaller, error) {
	ts := &TestSignaller{}
	if err := ts.setup(); err != nil {
		if cleanupErr := ts.Close(); err != nil {
			err = multierror.Append(err, cleanupErr)
		}
		return nil, err
	}
	return ts, nil
}

func (s *TestSignaller) setup() error {
	f, err := os.CreateTemp("", "test-signal-*")
	if err != nil {
		return fmt.Errorf("failed to create signal file: %v", err)
	}
	f.Close()
	s.fileName = f.Name()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create fsnotify watcher: %v", err)
	}
	s.watcher = watcher

	if err := watcher.Add(f.Name()); err != nil {
		return fmt.Errorf("failed to add a watch for %s to fsnotifty watcher: %v", f.Name(), err)
	}
	return nil
}

func (s *TestSignaller) Close() error {
	var result error
	if s.fileName != "" {
		if err := os.Remove(s.fileName); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.watcher != nil {
		if err := s.watcher.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

func (s *TestSignaller) Name() string {
	return s.fileName
}

func (s *TestSignaller) Await(timeout time.Duration) error {
	select {
	case event := <-s.watcher.Events:
		switch event.Op {
		case fsnotify.Create, fsnotify.Write:
			return nil
		default:
			return fmt.Errorf("got unexpected fsnotify event (name=%s op=%s)", event.Name, event.Op.String())
		}
	case err := <-s.watcher.Errors:
		return fmt.Errorf("fsnotify watcher returned error: %v", err)
	case <-time.After(timeout):
		return fmt.Errorf("timed out awaiting fsnotify event")
	}
}

// TestShim wraps some common code that will be needed by all tests: setting
// up and tearing down a shim involves creating and removing files to hold
// stdout and stderr and creating the shim command or struct according to
// the partcular test.
type TestShim struct {
	command            string
	args               []string
	killTimeoutSeconds int
	stdoutFile         string
	stderrFile         string
}

func NewTestShim(command string, args ...string) *TestShim {
	return &TestShim{
		command:            command,
		args:               args,
		killTimeoutSeconds: 2,
		stdoutFile:         fmt.Sprintf("/tmp/test-stdout-%d", rand.Int()),
		stderrFile:         fmt.Sprintf("/tmp/test-stderr-%d", rand.Int()),
	}
}

func (s *TestShim) Cleanup() error {
	var result error
	if s.stdoutFile != "" {
		if err := os.Remove(s.stdoutFile); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.stderrFile != "" {
		if err := os.Remove(s.stderrFile); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

func (s *TestShim) Stdout() string {
	return s.stdoutFile
}

func (s *TestShim) runSpec() RunSpec {
	return RunSpec{
		Command:            s.command,
		Args:               s.args,
		Limits:             TestLimits,
		CgroupRootDir:      TestCgroupRoot,
		OutputFile:         s.stdoutFile,
		ErrorFile:          s.stderrFile,
		KillTimeoutSeconds: s.killTimeoutSeconds,
		doNotMountProc:     true, // does not affect Command()
	}
}

func (s *TestShim) Shim() (*shim, error) {
	return newShim(s.runSpec())
}

func (s *TestShim) Command() (*exec.Cmd, error) {
	return ShimCommand(s.runSpec())
}

// parse the output of /proc/<pid>/ns/<namespace>; return the
// integer identifier of the namespace
func parseNamespace(content string) (uint64, error) {
	parts := strings.Split(content, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("content %q has unexpected format", content)
	}
	integer := strings.Trim(parts[1], "[]\n")
	return strconv.ParseUint(integer, 10, 64)
}

// This test checks for compliance of the shim with the requirement
// to launch the process in distinct PID, network, and mount namespaces.
func TestShim_DistinctNamespaces(t *testing.T) {
	testCases := []struct {
		description string
		pidFile     string
		invert      bool
	}{
		{
			description: "Ensure PID namespace is unique",
			pidFile:     "/proc/self/ns/pid",
		},
		{
			description: "Ensure network namespace is unique",
			pidFile:     "/proc/self/ns/net",
		},
		{
			description: "Ensure mount namespace is unique",
			pidFile:     "/proc/self/ns/mnt",
		},
		{
			description: "Ensure user namespace is not unique",
			pidFile:     "/proc/self/ns/user",
			invert:      true,
		},
		{
			description: "Ensure IPC namespace is not unique",
			pidFile:     "/proc/self/ns/ipc",
			invert:      true,
		},
		{
			description: "Ensure UTS namespace is not unique",
			pidFile:     "/proc/self/ns/uts",
			invert:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			ts := NewTestShim("/bin/readlink", testCase.pidFile)
			defer ts.Cleanup()

			shim, err := ts.Command()
			if err != nil {
				t.Fatalf("error creating shim Cmd: %v", err)
			}

			if err := shim.Run(); err != nil {
				t.Fatalf("error running shim process: %v", err)
			}

			resultBytes, err := os.ReadFile(ts.Stdout())
			if err != nil {
				t.Fatalf("error reading result: %v", err)
			}

			childNamespace, err := parseNamespace(string(resultBytes))
			if err != nil {
				t.Fatalf("error parsing child namespace: %v", err)
			}

			cmd := exec.Command("/bin/readlink", testCase.pidFile)
			outBuf := &bytes.Buffer{}
			cmd.Stdout = outBuf

			if err := cmd.Run(); err != nil {
				t.Fatalf("error getting parent namespace: %v", err)
			}
			parentNamespace, err := parseNamespace(outBuf.String())
			if err != nil {
				t.Fatalf("error parsing parent namespace: %v", err)
			}

			if (parentNamespace == childNamespace) != testCase.invert {
				t.Fatalf("namespaces not as expected")
			}
		})
	}
}

func TestShim_StopSignals(t *testing.T) {
	testCases := []struct {
		description string
		// format string; will sprintf with name of signal file as first arg
		scriptPattern string
		// expected exit signal on call to Stop()
		expectedSignal os.Signal
	}{
		{
			description:    "shim sends SIGTERM on Stop() call",
			scriptPattern:  "echo starting > %s; sleep 60;",
			expectedSignal: syscall.SIGTERM,
		},
		{
			description:    "shim escalates to SIGKILL if SIGTERM ignored",
			scriptPattern:  "trap : SIGTERM; echo starting > %s; sleep 60;",
			expectedSignal: syscall.SIGKILL,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			sig, err := NewTestSignaller()
			if err != nil {
				t.Fatalf("error creating signaller: %v", err)
			}
			defer sig.Close()

			script := fmt.Sprintf(testCase.scriptPattern, sig.Name())
			ts := NewTestShim("/bin/bash", "-c", script)
			defer ts.Cleanup()

			shim, err := ts.Shim()
			if err != nil {
				t.Fatalf("error running process: %v", err)
			}
			defer shim.Cleanup()

			if err := sig.Await(3 * time.Second); err != nil {
				t.Fatalf("error awaiting signal: %v", err)
			}

			if err := shim.Stop(); err != nil {
				t.Fatalf("error stopping process: %v", err)
			}

			status := shim.cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !status.Signaled() {
				t.Fatalf("process did not exit as the result of a signal")
			} else if sig := status.Signal(); sig != testCase.expectedSignal {
				t.Fatalf("process exited as a result of signal %v (expected %v)", sig, testCase.expectedSignal)
			}
		})
	}
}
