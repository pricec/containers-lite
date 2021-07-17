package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	multierror "github.com/hashicorp/go-multierror"
	pb "github.com/pricec/containers-lite/pb"
	"github.com/pricec/containers-lite/pkg/process"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

var (
	TestDisk       string
	TestCgroupRoot string
	TestLimits     = &pb.ResourceLimits{
		MemoryInMib:   100,
		CpuMillicores: 300,
		DiskReadMbps:  100,
		DiskWriteMbps: 100,
	}
)

func init() {
	process.Reexec()

	if TestDisk = os.Getenv("TEST_DISK"); TestDisk == "" {
		TestDisk = "sda"
	}
	if TestCgroupRoot = os.Getenv("TEST_CGROUP_ROOT"); TestCgroupRoot == "" {
		TestCgroupRoot = "/sys/fs/cgroup"
	}
}

// Note: Do not use math/rand for TLS in production
var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// selfSignedCert produces a self-signed X.509 Certificate with the given signer
func selfSignedCert(cn string, signer crypto.Signer) (*x509.Certificate, error) {
	return signedCert(cn, nil, nil, signer)
}

// signedCert creates an X.509 certificate. If `parent` is nil, the created
// certificate will be self-signed (Issuer == Subject) and `pub` will be ignored.
func signedCert(cn string, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              []string{cn},
		SerialNumber:          big.NewInt(0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	if parent == nil {
		parent = template
		pub = priv.Public()
	}

	certBytes, err := x509.CreateCertificate(rng, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ecdsaTLSCertificate generates a tls certificate from an
// ecdsa private key and a cert.
func ecdsaTLSCertificate(cert *x509.Certificate, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	tlsKeyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: tlsKeyDER,
		}),
	)
}

type TestServer struct {
	listener     *bufconn.Listener
	server       *WorkerServiceServer
	clientConn   *grpc.ClientConn
	clientCertCN string
	serverCertCN string
	// Root CA key signing server TLS cert
	serverRootKey *ecdsa.PrivateKey
	// Cert pool for use by server - trusts client root cert
	serverCertPool *x509.CertPool
	// Root CA key signing client TLS cert
	clientRootKey *ecdsa.PrivateKey
	// Cert pool for use by client - trusts server root cert
	clientCertPool *x509.CertPool
	// Server's private key
	serverKey *ecdsa.PrivateKey
	// Server's TLS certificate
	serverCert tls.Certificate
	// Client's private key
	clientKey *ecdsa.PrivateKey
	// Client's TLS certificate
	clientCert tls.Certificate
}

func NewTestServer() (*TestServer, error) {
	s := &TestServer{
		listener:     bufconn.Listen(1024 * 1024),
		clientCertCN: "client",
		serverCertCN: "server",
	}

	if err := s.generateKeys(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *TestServer) generateKeys() error {
	var err error
	keys := make([]*ecdsa.PrivateKey, 4)
	for i, _ := range keys {
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rng)
		if err != nil {
			return err
		}
	}

	s.serverRootKey = keys[0]
	s.clientRootKey = keys[1]
	s.serverKey = keys[2]
	s.clientKey = keys[3]

	serverRootCert, err := selfSignedCert("server-ca", s.serverRootKey)
	if err != nil {
		return err
	}
	s.clientCertPool = x509.NewCertPool()
	s.clientCertPool.AddCert(serverRootCert)

	clientRootCert, err := selfSignedCert("client-ca", s.clientRootKey)
	if err != nil {
		return err
	}
	s.serverCertPool = x509.NewCertPool()
	s.serverCertPool.AddCert(clientRootCert)

	serverCert, err := signedCert(s.serverCertCN, serverRootCert, s.serverKey.Public(), s.serverRootKey)
	if err != nil {
		return err
	}
	s.serverCert, err = ecdsaTLSCertificate(serverCert, s.serverKey)
	if err != nil {
		return err
	}

	clientCert, err := signedCert(s.clientCertCN, clientRootCert, s.clientKey.Public(), s.clientRootKey)
	if err != nil {
		return err
	}
	s.clientCert, err = ecdsaTLSCertificate(clientCert, s.clientKey)
	if err != nil {
		return err
	}

	return nil
}

func (s *TestServer) Close() error {
	var result error

	if s.server != nil {
		if err := s.server.Close(0); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if s.clientConn != nil {
		if err := s.clientConn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if err := s.listener.Close(); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func (s *TestServer) DefaultServerOptions() ServerOptions {
	return ServerOptions{
		CACertPool:  s.serverCertPool,
		Certificate: s.serverCert,
		Authorizer: NewAuthzInterceptor(AuthzInterceptorOptions{
			Permissions: map[string][]string{
				s.clientCertCN: AllEndpoints,
			},
		}),
		DiskLimitDevice:    TestDisk,
		CgroupRootDir:      TestCgroupRoot,
		KillTimeoutSeconds: 3,
		Listener:           s.listener,
	}
}

func (s *TestServer) Server() (*WorkerServiceServer, error) {
	return s.ServerFromOptions(s.DefaultServerOptions())
}

func (s *TestServer) ServerFromOptions(opts ServerOptions) (*WorkerServiceServer, error) {
	server, err := NewServer(opts)
	if err != nil {
		return nil, err
	}

	s.server = server
	return s.server, nil
}

func (s *TestServer) Client(ctx context.Context) (pb.WorkerServiceClient, error) {
	conn, err := grpc.DialContext(
		ctx,
		s.listener.Addr().String(),
		grpc.WithContextDialer(
			func(context.Context, string) (net.Conn, error) {
				return s.listener.Dial()
			},
		),
		grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				ServerName:   s.serverCertCN,
				Certificates: []tls.Certificate{s.clientCert},
				RootCAs:      s.clientCertPool,
			}),
		),
	)
	if err != nil {
		return nil, err
	}

	s.clientConn = conn
	return pb.NewWorkerServiceClient(conn), nil
}

func (s *TestServer) ClientServer(ctx context.Context) (*WorkerServiceServer, pb.WorkerServiceClient, error) {
	server, err := s.Server()
	if err != nil {
		return nil, nil, err
	}

	client, err := s.Client(ctx)
	if err != nil {
		if closeErr := s.Close(); err != nil {
			err = multierror.Append(err, closeErr)
		}
		return nil, nil, err
	}

	return server, client, nil
}

type outputReceiver interface {
	Recv() (*pb.ProcessOutput, error)
}

// This test ensures the server returns stdout/stderr as expected.
func TestServer_Output(t *testing.T) {
	stdout := uuid.New().String()
	stderr := uuid.New().String()

	testCases := []struct {
		description    string
		script         string // bash script to run
		expectedOutput string
		stdout         bool // if true, read stdout. if false, read stderr
	}{
		{
			description:    "ensure stdout is returned correctly",
			script:         fmt.Sprintf("printf %s;", stdout),
			expectedOutput: stdout,
			stdout:         true,
		},
		{
			description:    "ensure stderr is returned correctly",
			script:         fmt.Sprintf("printf %s > /dev/stderr;", stderr),
			expectedOutput: stderr,
			stdout:         false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			ts, err := NewTestServer()
			if err != nil {
				t.Fatalf("error creating TestServer: %v", err)
			}
			t.Cleanup(func() {
				if err := ts.Close(); err != nil {
					t.Fatalf("TestServer errored on close: %v", err)
				}
			})

			ctx := context.Background()
			_, client, err := ts.ClientServer(ctx)
			if err != nil {
				t.Fatalf("error creating client and server: %v", err)
			}

			handle, err := client.Create(ctx, &pb.LaunchConfiguration{
				Command: "/bin/bash",
				Args:    []string{"-c", testCase.script},
				Limits:  TestLimits,
			})
			if err != nil {
				t.Fatalf("error creating process: %v", err)
			}

			outputFunc := func(ctx context.Context, in *pb.OutputRequest, opts ...grpc.CallOption) (outputReceiver, error) {
				return client.Output(ctx, in, opts...)
			}
			if !testCase.stdout {
				outputFunc = func(ctx context.Context, in *pb.OutputRequest, opts ...grpc.CallOption) (outputReceiver, error) {
					return client.Error(ctx, in, opts...)
				}
			}

			outStream, err := outputFunc(ctx, &pb.OutputRequest{
				Id:     handle,
				Stream: true,
			})
			if err != nil {
				t.Fatalf("error getting output stream: %v", err)
			}

			output := &bytes.Buffer{}
			var s *pb.ProcessOutput
			for err == nil {
				s, err = outStream.Recv()
				if err != nil && err != io.EOF {
					t.Fatalf("error reading from stream: %v", err)
				}
				output.Write(s.GetValue())
			}

			if output.String() != testCase.expectedOutput {
				t.Fatalf("unexpected stdout %s (expected %s)", output.String(), testCase.expectedOutput)
			}
		})
	}
}

// This test contains a set of cases to exercise authn and authz scenarios
func TestServer_Authnz(t *testing.T) {
	testCases := []struct {
		description  string
		getOptions   func(*TestServer) ServerOptions
		actionFunc   func(context.Context, pb.WorkerServiceClient) error
		expectedCode codes.Code
	}{
		{
			description: "ensure unary request can be authenticated and authorized",
			getOptions: func(ts *TestServer) ServerOptions {
				return ts.DefaultServerOptions()
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				_, err := client.Status(ctx, &pb.ProcessHandle{Value: "test"})
				return err
			},
			expectedCode: codes.NotFound,
		},
		{
			description: "ensure stream request can be authenticated and authorized",
			getOptions: func(ts *TestServer) ServerOptions {
				return ts.DefaultServerOptions()
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				outStream, err := client.Output(ctx, &pb.OutputRequest{
					Id: &pb.ProcessHandle{Value: "test"},
				})
				if err != nil {
					return err
				}

				_, err = outStream.Recv()
				return err
			},
			expectedCode: codes.NotFound,
		},
		{
			description: "ensure request is unauthenticated with unverifiable client cert",
			getOptions: func(ts *TestServer) ServerOptions {
				opts := ts.DefaultServerOptions()
				opts.CACertPool = ts.clientCertPool
				return opts
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				_, err := client.Stop(ctx, &pb.ProcessHandle{Value: "test"})
				return err
			},
			expectedCode: codes.Unavailable,
		},
		{
			description: "ensure unauthorized requests to unary endpoints are rejected",
			getOptions: func(ts *TestServer) ServerOptions {
				opts := ts.DefaultServerOptions()
				opts.Authorizer = NewAuthzInterceptor(AuthzInterceptorOptions{
					Permissions: map[string][]string{},
				})
				return opts
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				_, err := client.Status(ctx, &pb.ProcessHandle{Value: "test"})
				return err
			},
			expectedCode: codes.PermissionDenied,
		},
		{
			description: "ensure unauthorized requests to stream endpoints are rejected",
			getOptions: func(ts *TestServer) ServerOptions {
				opts := ts.DefaultServerOptions()
				opts.Authorizer = NewAuthzInterceptor(AuthzInterceptorOptions{
					Permissions: map[string][]string{},
				})
				return opts
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				errStream, err := client.Error(ctx, &pb.OutputRequest{
					Id: &pb.ProcessHandle{Value: "test"},
				})
				if err != nil {
					return err
				}

				_, err = errStream.Recv()
				return err
			},
			expectedCode: codes.PermissionDenied,
		},
		{
			description: "ensure certificate client name must match permissions",
			getOptions: func(ts *TestServer) ServerOptions {
				opts := ts.DefaultServerOptions()
				opts.Authorizer = NewAuthzInterceptor(AuthzInterceptorOptions{
					Permissions: map[string][]string{
						fmt.Sprintf("x%s", ts.clientCertCN): AllEndpoints,
					},
				})
				return opts
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				_, err := client.Status(ctx, &pb.ProcessHandle{Value: "test"})
				return err
			},
			expectedCode: codes.PermissionDenied,
		},
		{
			description: "ensure unauthorized endpoints are disallowed",
			getOptions: func(ts *TestServer) ServerOptions {
				opts := ts.DefaultServerOptions()
				opts.Authorizer = NewAuthzInterceptor(AuthzInterceptorOptions{
					Permissions: map[string][]string{
						ts.clientCertCN: []string{
							"/WorkerService/Status",
						},
					},
				})
				return opts
			},
			actionFunc: func(ctx context.Context, client pb.WorkerServiceClient) error {
				_, err := client.Status(ctx, &pb.ProcessHandle{Value: "test"})
				if err != nil {
					if code := status.Code(err); code != codes.NotFound {
						return status.Error(codes.OK, "test failed")
					}
				}

				_, err = client.Stop(ctx, &pb.ProcessHandle{Value: "test"})
				return err
			},
			expectedCode: codes.PermissionDenied,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			ts, err := NewTestServer()
			if err != nil {
				t.Fatalf("error creating TestServer: %v", err)
			}
			t.Cleanup(func() {
				if err := ts.Close(); err != nil {
					t.Fatalf("error closing TestServer: %v", err)
				}
			})

			_, err = ts.ServerFromOptions(testCase.getOptions(ts))
			if err != nil {
				t.Fatalf("error creating server")
			}

			ctx := context.Background()
			client, err := ts.Client(ctx)
			if err != nil {
				t.Fatalf("error setting up client and server: %v", err)
			}

			err = testCase.actionFunc(ctx, client)
			if code := status.Code(err); code != testCase.expectedCode {
				t.Fatalf("unexpected status code %v (expected %v)", code, testCase.expectedCode)
			}
		})
	}
}
