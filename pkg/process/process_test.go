package process

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testProcess(command string, args ...string) (*Process, error) {
	return NewProcess(LaunchConfiguration{
		Command:            command,
		Args:               args,
		Limits:             TestLimits,
		CgroupRootDir:      TestCgroupRoot,
		KillTimeoutSeconds: 5,
	})
}

// This test ensures Status() returns Started when the process is running
// and Stopped after a successful call to Stop().
func TestProcess_StatusStopped(t *testing.T) {
	sig, err := NewTestSignaller()
	if err != nil {
		t.Fatalf("error creating signaller: %v", err)
	}
	defer sig.Close()

	p, err := testProcess("/bin/bash", "-c", fmt.Sprintf("echo starting > %s; sleep 30;", sig.Name()))
	if err != nil {
		t.Fatalf("error creating process: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Cleanup(); err != nil {
			t.Fatalf("error cleaning up process: %v", err)
		}
	})

	if err := sig.Await(3 * time.Second); err != nil {
		t.Fatalf("error awaiting start signal: %v", err)
	}

	if state := p.Status().State; state != StateStarted {
		t.Fatalf("unexpected state %v (expected %v)", state, StateStarted)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("error stopping process: %v", err)
	}

	if state := p.Status().State; state != StateStopped {
		t.Fatalf("unexpected state %v (expected %v)", state, StateStopped)
	}
}

// This test ensures that Status() returns exited after the process
// has finished running.
func TestProcess_StatusExited(t *testing.T) {
	p, err := testProcess("/bin/ls")
	if err != nil {
		t.Fatalf("error creating process: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Cleanup(); err != nil {
			t.Fatalf("error cleaning up process: %v", err)
		}
	})

	if err := p.wait(3 * time.Second); err != nil {
		t.Fatalf("error waiting for process: %v", err)
	}

	if state := p.Status().State; state != StateExited {
		t.Fatalf("unexpected state %v (expected %v)", state, StateExited)
	}
}

// This test ensures that Stdout returns precisely what was written
// to stdout by the process.
func TestProcess_Stdout(t *testing.T) {
	str := uuid.New().String()
	p, err := testProcess("/usr/bin/printf", str)
	if err != nil {
		t.Fatalf("error creating process: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Cleanup(); err != nil {
			t.Fatalf("error cleaning up process: %v", err)
		}
	})

	out, err := p.Stdout(true)
	if err != nil {
		t.Fatalf("error getting stdout: %v", err)
	}

	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("error reading output: %v", err)
	}

	if string(outBytes) != str {
		t.Fatalf("got unexpected output %s (expected %s)", string(outBytes), str)
	}
}

// This test ensures that Stderr returns precisely what was written
// to stderr by the process.
func TestProcess_Stderr(t *testing.T) {
	str := uuid.New().String()
	p, err := testProcess("/bin/bash", "-c", fmt.Sprintf("/usr/bin/printf %s > /dev/stderr;", str))
	if err != nil {
		t.Fatalf("error creating process: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Cleanup(); err != nil {
			t.Fatalf("error cleaning up process: %v", err)
		}
	})

	out, err := p.Stderr(true)
	if err != nil {
		t.Fatalf("error getting stderr: %v", err)
	}

	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("error reading output: %v", err)
	}

	if string(outBytes) != str {
		t.Fatalf("got unexpected output %s (expected %s)", string(outBytes), str)
	}
}
