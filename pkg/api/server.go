package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/pricec/containers-lite/pb"
	"github.com/pricec/containers-lite/pkg/process"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	UnprivilegedEndpoints = []string{
		"/WorkerService/Status",
		"/WorkerService/Output",
		"/WorkerService/Error",
	}
	AllEndpoints = append(
		UnprivilegedEndpoints,
		"/WorkerService/Create",
		"/WorkerService/Stop",
	)
)

type WorkerServiceServer struct {
	pb.UnimplementedWorkerServiceServer
	processes          *sync.Map
	grpcServer         *grpc.Server
	diskLimitDevice    string
	cgroupRootDir      string
	killTimeoutSeconds int
	doneCh             chan struct{} // memory barrier for exitErr
	exitErr            error
}

type ServerOptions struct {
	// CertPool containing trusted root certificates; used to
	// verify client certificates
	CACertPool *x509.CertPool
	// Server TLS certificate
	Certificate tls.Certificate
	// Authorization rules
	Authorizer *AuthzInterceptor
	// Address to bind listen socket (if Listener == nil)
	BindAddr string
	// Listener port (if Listener == nil)
	Port uint
	// Block device to apply disk speed limits to (likely "sda")
	DiskLimitDevice string
	// Root directory in which to create cgroups (likely "/sys/fs/cgroup")
	CgroupRootDir string
	// Number of seconds to wait for termination after SIGTERM
	// before escalating to SIGKILL.
	KillTimeoutSeconds int
	// Optional Listener. Mostly useful for testing. If Listener == nil,
	// then a new TCP Listener will be created based on BindAddr and Port.
	Listener net.Listener
}

// NewServer creates a WorkerServiceServer from the argument ServerOptions
// and starts it running in a new goroutine. Note that, if the returned
// error is nil, it is up to the caller to call Close() on the returned
// *WorkerServiceServer.
func NewServer(opts ServerOptions) (*WorkerServiceServer, error) {
	grpcOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(&tls.Config{
			ClientAuth:               tls.RequireAndVerifyClientCert,
			Certificates:             []tls.Certificate{opts.Certificate},
			ClientCAs:                opts.CACertPool,
			MinVersion:               tls.VersionTLS13,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
		})),
		grpc.UnaryInterceptor(opts.Authorizer.Unary()),
		grpc.StreamInterceptor(opts.Authorizer.Stream()),
	}

	server := &WorkerServiceServer{
		processes:          &sync.Map{},
		grpcServer:         grpc.NewServer(grpcOpts...),
		diskLimitDevice:    opts.DiskLimitDevice,
		cgroupRootDir:      opts.CgroupRootDir,
		killTimeoutSeconds: opts.KillTimeoutSeconds,
		doneCh:             make(chan struct{}),
	}
	pb.RegisterWorkerServiceServer(server.grpcServer, server)

	lis := opts.Listener
	if lis == nil {
		var err error
		lis, err = net.Listen("tcp", fmt.Sprintf("%s:%d", opts.BindAddr, opts.Port))
		if err != nil {
			return nil, err
		}
	}

	go func() {
		defer close(server.doneCh)
		server.exitErr = server.grpcServer.Serve(lis)
	}()

	return server, nil
}

// Wait for the server to exit and return the error encountered while running.
func (s *WorkerServiceServer) Wait() error {
	<-s.doneCh
	return s.exitErr
}

// Close first attempts to gracefully shut down the server, which stops
// accepting incoming connections but continues processing existing ones.
// If the timeout elapses and the server still has not shut down, then
// the server is forcefully closed. After the server is shut down, any
// allocated resources are cleaned up.
func (s *WorkerServiceServer) Close(timeout time.Duration) error {
	select {
	case <-s.doneCh:
	default:
		s.grpcServer.GracefulStop()

		select {
		case <-time.After(timeout):
			s.grpcServer.Stop()
		case <-s.doneCh:
		}
	}

	return s.cleanup()
}

// cleanup should be called when the consumer is finished using the
// server; persisent resources will be cleaned up and released. This
// function should not generally be called; use Close() instead.
func (s *WorkerServiceServer) cleanup() error {
	var result error
	processes := make(map[string]*process.Process)
	s.processes.Range(func(key, value interface{}) bool {
		processes[key.(string)] = value.(*process.Process)
		return true
	})

	for id, ps := range processes {
		if err := ps.Cleanup(); err != nil {
			result = multierror.Append(result, err)
		}
		s.processes.Delete(id)
	}
	return result
}

// Create implements the Create RPC. It creates a new process and starts it.
func (s *WorkerServiceServer) Create(ctx context.Context, config *pb.LaunchConfiguration) (*pb.ProcessHandle, error) {
	ps, err := process.NewProcess(process.LaunchConfiguration{
		Command: config.Command,
		Args:    config.Args,
		Limits: process.ResourceLimits{
			MemoryInMiB:     int(config.Limits.MemoryInMib),
			CPUMillicores:   int(config.Limits.CpuMillicores),
			DiskReadMBPS:    int(config.Limits.DiskReadMbps),
			DiskWriteMBPS:   int(config.Limits.DiskWriteMbps),
			DiskLimitDevice: s.diskLimitDevice,
		},
		CgroupRootDir:      s.cgroupRootDir,
		KillTimeoutSeconds: s.killTimeoutSeconds,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"request": config,
		}).Warnf("error creating process: %v", err)
		return nil, status.Error(codes.Internal, "error setting up process")
	}

	return &pb.ProcessHandle{
		Value: s.addProcess(ps),
	}, nil
}

// Stop implements the Stop RPC. It attempts to stop the process, if running.
func (s *WorkerServiceServer) Stop(ctx context.Context, id *pb.ProcessHandle) (*emptypb.Empty, error) {
	ps, err := s.process(id)
	if err != nil {
		return nil, err
	}

	if err := ps.Stop(); err != nil {
		logrus.WithFields(logrus.Fields{
			"ProcessHandle": id.GetValue(),
		}).Warnf("error stopping process: %v", err)
		return nil, status.Error(codes.Internal, "error stopping process")
	}
	return &emptypb.Empty{}, nil
}

// Status implements the Status RPC.
func (s *WorkerServiceServer) Status(ctx context.Context, id *pb.ProcessHandle) (*pb.ProcessStatus, error) {
	ps, err := s.process(id)
	if err != nil {
		return nil, err
	}

	status := ps.Status()
	result := &pb.ProcessStatus{
		ExitCode: int32(status.ExitCode),
	}

	if status.ExitErr != nil {
		result.ExitError = status.ExitErr.Error()
	}

	switch status.State {
	case process.StateStarted:
		result.State = pb.ProcessStatus_STARTED
	case process.StateStopped:
		result.State = pb.ProcessStatus_STOPPED
	case process.StateExited:
		result.State = pb.ProcessStatus_EXITED
	default:
		logrus.Warnf("Unrecognized process status: %v", status.State)
	}
	return result, nil
}

// Output implements the Output RPC.
func (s *WorkerServiceServer) Output(req *pb.OutputRequest, stream pb.WorkerService_OutputServer) error {
	ps, err := s.process(req.GetId())
	if err != nil {
		return err
	}

	return s.output(stream, func() (io.ReadCloser, error) {
		return ps.Stdout(req.GetStream())
	})
}

// Error implements the Error RPC.
func (s *WorkerServiceServer) Error(req *pb.OutputRequest, stream pb.WorkerService_ErrorServer) error {
	ps, err := s.process(req.GetId())
	if err != nil {
		return err
	}

	return s.output(stream, func() (io.ReadCloser, error) {
		return ps.Stderr(req.GetStream())
	})
}

// outputSender allows the output function to be used with both the
// pb.WorkerService_OutputServer and pb.WorkerService_ErrorServer types
type outputSender interface {
	Send(*pb.ProcessOutput) error
}

func (s *WorkerServiceServer) output(stream outputSender, getOutput func() (io.ReadCloser, error)) error {
	output, err := getOutput()
	if err != nil {
		logrus.Warnf("failed to get output stream: %v", err)
		return status.Error(codes.Internal, "failed to create output stream")
	}
	defer output.Close()

	var n int
	buf := make([]byte, 512)
	for err != io.EOF {
		n, err = output.Read(buf)
		if err != nil && err != io.EOF {
			logrus.Warnf("error reading output: %v", err)
			return status.Error(codes.Internal, "error reading output")
		}

		if n > 0 {
			if sendErr := stream.Send(&pb.ProcessOutput{Value: buf[:n]}); sendErr != nil {
				logrus.Warnf("error sending output: %v", sendErr)
				return status.Error(codes.Internal, "error sending output to client")
			}
		}
	}
	return nil
}

// addProcess generates a process handle, adds the process to the processes
// map and returns the generated handle.
func (s *WorkerServiceServer) addProcess(ps *process.Process) string {
	var id string
	loaded := true
	// Retry to handle the (exeedingly unlikely) possibility that
	// there is already a stored process with the generated handle.
	for loaded {
		id = uuid.New().String()
		_, loaded = s.processes.LoadOrStore(id, ps)
	}
	return id
}

// process looks up and returns the process referred to by the argument
// ProcessHandle. The returned error, if non-nil, is safe to return to
// the client.
func (s *WorkerServiceServer) process(id *pb.ProcessHandle) (*process.Process, error) {
	ps, exists := s.processes.Load(id.GetValue())
	if !exists {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("no such process with ID %v", id.GetValue()))
	}
	return ps.(*process.Process), nil
}

// deleteAndReturnProcess deletes the process referred to by the argument
// ProcessHandle from the list of processes, and returns the Process. The
// returned error, if non-nil, is safe to return to the client.
func (s *WorkerServiceServer) deleteAndReturnProcess(id *pb.ProcessHandle) (*process.Process, error) {
	ps, exists := s.processes.LoadAndDelete(id.GetValue())
	if !exists {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("no such process with ID %v", id.GetValue()))
	}
	return ps.(*process.Process), nil
}
