package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pricec/containers-lite/pkg/api"
	"github.com/pricec/containers-lite/pkg/process"
	"github.com/sirupsen/logrus"
)

var (
	bindAddr           string
	port               uint
	caCertPath         string
	serverCertPath     string
	serverKeyPath      string
	adminCN            string
	userCN             string
	debug              bool
	diskLimitDevice    string
	cgroupRootDir      string
	killTimeoutSeconds int

	stopTimeout = 15 * time.Second
)

func main() {
	process.Reexec()

	flag.BoolVar(&debug, "debug", false, "set debug log level")
	flag.UintVar(&port, "port", 8888, "server bind port")
	flag.StringVar(&bindAddr, "bind-addr", "localhost", "server bind address")
	flag.StringVar(&caCertPath, "ca-cert", "", "path to CA certificate")
	flag.StringVar(&serverCertPath, "cert", "", "path to server TLS certificate")
	flag.StringVar(&serverKeyPath, "key", "", "path to server TLS key")
	flag.StringVar(&adminCN, "admin-cn", "", "common name of mTLS client cert to grant full API access")
	flag.StringVar(&userCN, "user-cn", "", "common name of mTLS client cert to grant read-only API access")
	flag.StringVar(&diskLimitDevice, "disk-limit", "sda", "block device to apply disk speed limits")
	flag.StringVar(&cgroupRootDir, "cgroup-root-dir", "/sys/fs/cgroup", "root cgroup directory to use")
	flag.IntVar(&killTimeoutSeconds, "kill-timeout", 5, "number of seconds to wait between SIGTERM and SIGKILL")
	flag.Parse()

	// Logging setup
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// TLS setup
	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"serverCertPath": serverCertPath,
			"serverKeyPath":  serverKeyPath,
		}).Fatalf("Error loading TLS keypair: %v", err)
	}

	certPool := x509.NewCertPool()
	caCertBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"caCertPath": caCertPath,
		}).Fatalf("Error loading CA certificate: %v", err)
	}

	if !certPool.AppendCertsFromPEM(caCertBytes) {
		logrus.Fatalf("Failed to add CA cert to cert pool")
	}

	apiServer, err := api.NewServer(api.ServerOptions{
		CACertPool:  certPool,
		Certificate: certificate,
		Authorizer: api.NewAuthzInterceptor(api.AuthzInterceptorOptions{
			Permissions: map[string][]string{
				adminCN: api.AllEndpoints,
				userCN:  api.UnprivilegedEndpoints,
			},
		}),
		BindAddr:           bindAddr,
		Port:               port,
		DiskLimitDevice:    diskLimitDevice,
		CgroupRootDir:      cgroupRootDir,
		KillTimeoutSeconds: killTimeoutSeconds,
	})
	if err != nil {
		logrus.Fatalf("error starting server: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			_, ok := <-sigChan
			if !ok {
				return
			}

			if err := apiServer.Close(stopTimeout); err != nil {
				logrus.Errorf("error stopping API server: %v", err)
			}
		}
	}()

	if err := apiServer.Wait(); err != nil {
		logrus.Warnf("API server exited with error: %v", err)
	}
}
