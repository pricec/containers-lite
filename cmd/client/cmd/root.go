package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	host           string
	port           int
	caCertPath     string
	clientCertPath string
	clientKeyPath  string
	serverName     string
	conn           *grpc.ClientConn
	client         pb.WorkerServiceClient

	rootCmd = &cobra.Command{
		Use:   "client",
		Short: "Client CLI for process runner app",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			certificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
			if err != nil {
				return err
			}

			certPool := x509.NewCertPool()
			caCertBytes, err := os.ReadFile(caCertPath)
			if err != nil {
				return err
			}

			if !certPool.AppendCertsFromPEM(caCertBytes) {
				return fmt.Errorf("failed to add CA cert to CertPool")
			}

			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(
					credentials.NewTLS(&tls.Config{
						ServerName:   serverName,
						Certificates: []tls.Certificate{certificate},
						RootCAs:      certPool,
					}),
				),
			}
			conn, err = grpc.DialContext(
				cmd.Context(),
				fmt.Sprintf("%s:%d", host, port),
				opts...,
			)
			client = pb.NewWorkerServiceClient(conn)
			return err
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if conn != nil {
				return conn.Close()
			}
			return nil
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&host, "server", "s", "localhost", "server hostname")
	rootCmd.PersistentFlags().IntVarP(&port, "port", "p", 8888, "server port")
	rootCmd.PersistentFlags().StringVar(&caCertPath, "ca-cert", "", "CA certificate path")
	rootCmd.PersistentFlags().StringVar(&clientCertPath, "cert", "", "client certificate path")
	rootCmd.PersistentFlags().StringVar(&clientKeyPath, "key", "", "client key path")
	rootCmd.PersistentFlags().StringVar(&serverName, "server-name", "", "server name for TLS certificate verification")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
