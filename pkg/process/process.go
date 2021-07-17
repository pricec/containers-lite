package process

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	multierror "github.com/hashicorp/go-multierror"
)

type ProcessState uint8

const (
	StateStarted ProcessState = iota // Process is running
	StateStopped ProcessState = iota // Process has been stopped by a call to Stop()
	StateExited  ProcessState = iota // Process has exited on its own
)

func (s ProcessState) String() string {
	switch s {
	case StateStarted:
		return "STARTED"
	case StateStopped:
		return "STOPPED"
	case StateExited:
		return "EXITED"
	default:
		return "UNKNOWN"
	}
}

const (
	// Extra time to add to consumer stop timeout to allow shim to
	// escalate to SIGKILL if necessary.
	shimTimeoutBuffer = 3
)

type ProcessStatus struct {
	State    ProcessState
	ExitCode int
	ExitErr  error
}

type LaunchConfiguration struct {
	Command            string
	Args               []string
	Limits             ResourceLimits
	CgroupRootDir      string
	KillTimeoutSeconds int
}

type Process struct {
	cmd                *exec.Cmd
	outFile            string
	errFile            string
	killTimeoutSeconds int

	doneCh   chan struct{} // memory barrier for exitErr, exitCode, stopped
	exitErr  error
	exitCode int
	stopped  bool

	signalMtx sync.Mutex // protects the value of signalled
	signalled bool
}

// NewProcess creates a new Process based on the supplied LaunchConfiguration
// and starts it running. If the returned error is nil, then it is up to
// the caller to call Cleanup() on the returned process when finished with it.
func NewProcess(cfg LaunchConfiguration) (*Process, error) {
	outFile, errFile, err := createOutFiles()
	if err != nil {
		return nil, err
	}

	p := &Process{
		doneCh:             make(chan struct{}),
		outFile:            outFile,
		errFile:            errFile,
		killTimeoutSeconds: cfg.KillTimeoutSeconds + shimTimeoutBuffer,
	}

	if err := p.start(cfg); err != nil {
		if cleanupErr := p.Cleanup(); cleanupErr != nil {
			return nil, multierror.Append(err, cleanupErr)
		}
		return nil, err
	}
	return p, nil
}

// start the process.
func (p *Process) start(cfg LaunchConfiguration) error {
	cmd, err := ShimCommand(RunSpec{
		Command:            cfg.Command,
		Args:               cfg.Args,
		Limits:             cfg.Limits,
		CgroupRootDir:      cfg.CgroupRootDir,
		OutputFile:         p.outFile,
		ErrorFile:          p.errFile,
		KillTimeoutSeconds: cfg.KillTimeoutSeconds,
	})
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	p.cmd = cmd

	go func() {
		defer close(p.doneCh)
		p.exitErr = cmd.Wait()
		p.exitCode = cmd.ProcessState.ExitCode()
		p.stopped = p.stopSignalled()
	}()

	return nil
}

// Cleanup destroys the process (if running) and cleans up the resources
// in use by the Process. If Cleanup is not called, resources will be
// leaked. After a call to Cleanup, the Process should not be used.
func (p *Process) Cleanup() error {
	var result error
	if p.cmd != nil {
		if err := p.Stop(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if err := os.Remove(p.outFile); err != nil {
		result = multierror.Append(result, err)
	}

	if err := os.Remove(p.errFile); err != nil {
		result = multierror.Append(result, err)
	}
	return result
}

// Stop the process. An error will be returned if the process cannot
// be signalled or if it does not exit within the configured timeout.
func (p *Process) Stop() error {
	switch p.state() {
	case StateStopped, StateExited:
		return nil
	}

	if err := p.stopSignal(); err != nil {
		return err
	}

	select {
	case <-p.doneCh:
	case <-time.After(time.Second * time.Duration(p.killTimeoutSeconds)):
		return fmt.Errorf("timed out waiting for process to exit")
	}

	// We could get aggressive and send SIGKILL to the shim here,
	// but that would mean that the resources it has allocated will
	// not be cleaned up.

	return nil
}

// stopSignal sends a SIGTERM to the shim process and updates the value
// of p.signalled. This is necessary since the value of p.signalled should
// only be set after successfully sending a signal to the child; however,
// the waiter goroutine (in start()) might respond to the SIGTERM and
// set stopped equal to an incorrect value if p.signalled has not yet
// been set to true.
//
// It seems an ideal solution to this problem would be to use the
// syscall.WaitStatus available after the call to Wait() in start()
// returns. However, getting the shim process to actually exit with
// the correct wait status is a big challenge, since it has assumed
// PID 1 in its PID namespace, and therefore the kernel will not
// deliver to it any unhandled signals (with some minor exceptions -
// see pid_namespaces(7)).
func (p *Process) stopSignal() error {
	p.signalMtx.Lock()
	defer p.signalMtx.Unlock()

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	p.signalled = true
	return nil
}

func (p *Process) stopSignalled() bool {
	p.signalMtx.Lock()
	defer p.signalMtx.Unlock()

	return p.signalled
}

// Status returns the current status of the process. For the State:
// - StateStarted means the process is currently running
// - StateStopped means the process was stopped by a call to Stop()
// - StateExited means the process has completed on its own
// If the process has exited, the ExitCode and ExitErr will be populated.
func (p *Process) Status() ProcessStatus {
	status := ProcessStatus{
		State: p.state(),
	}

	switch status.State {
	case StateStopped, StateExited:
		status.ExitCode = p.exitCode
		status.ExitErr = p.exitErr
	}
	return status
}

// state returns the current state of the process. See Status() for
// a description of the meaning of each ProcessState.
func (p *Process) state() ProcessState {
	select {
	case <-p.doneCh:
	default:
		return StateStarted
	}

	if p.stopped {
		return StateStopped
	} else {
		return StateExited
	}
}

// Stdout returns an io.ReadCloser for the Stdout of the process.
// If stream is false, the ReadCloser will return io.EOF when the
// consumer reaches the end of the output generated so far, even
// if the process is still running. If stream is true, the ReadCloser
// will not return io.EOF until the process has exited. If there is
// no data to read from Stdout, and the process is still alive,
// reads will block indefinitely.
func (p *Process) Stdout(stream bool) (io.ReadCloser, error) {
	return p.output(p.outFile, stream)
}

// Stderr returns an io.ReadCloser for the Stderr of the process.
// If stream is false, the ReadCloser will return io.EOF when the
// consumer reaches the end of the errors generated so far, even
// if the process is still running. If stream is true, the ReadCloser
// will not return io.EOF until the process has exited. If there is
// no data to read from Stderr, and the process is still alive,
// reads will block indefinitely.
func (p *Process) Stderr(stream bool) (io.ReadCloser, error) {
	return p.output(p.errFile, stream)
}

func (p *Process) output(path string, stream bool) (io.ReadCloser, error) {
	if stream {
		return NewTailReader(TailReaderOptions{
			Path:   path,
			DoneCh: p.doneCh,
		})
	} else {
		return os.Open(path)
	}
}

// wait for the process to exit.
func (p *Process) wait(timeout time.Duration) error {
	select {
	case <-p.doneCh:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for process exit")
	}
}

// createOutFiles creates files for stdout and stderr, returning their
// names if successful and a non-nil error otherwise. If the returned
// error is non-nil, cleanup has been attempted (but is not guaranteed
// to have worked). It would be better to do this in the shim, but it
// causes a race where a call to NewProcess() followed by a call to
// Stdout() returns a file not found error. The os.CreateTemp function
// also ensures that the generated filename does not already exist.
func createOutFiles() (string, string, error) {
	stdout, err := os.CreateTemp("", "stdout-*")
	if err != nil {
		return "", "", err
	}
	stdout.Close()

	stderr, err := os.CreateTemp("", "stderr-*")
	if err != nil {
		return "", "", multierror.Append(err, os.Remove(stdout.Name()))
	}
	stderr.Close()
	return stdout.Name(), stderr.Name(), nil
}
