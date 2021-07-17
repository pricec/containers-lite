package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	streamErr bool

	errorCmd = &cobra.Command{
		Use:          "error [process ID]",
		Short:        "View process errors",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doOutput(cmd.Context(), args[0], streamErr, func(ctx context.Context, req *pb.OutputRequest, opts ...grpc.CallOption) (outputReceiver, error) {
				stream, err := client.Error(ctx, req, opts...)
				return stream, err
			})
		},
	}
)

func init() {
	errorCmd.Flags().BoolVar(&streamErr, "stream", false, "stream output")
	rootCmd.AddCommand(errorCmd)
}

type outputReceiver interface {
	Recv() (*pb.ProcessOutput, error)
}

type receiverFunc func(context.Context, *pb.OutputRequest, ...grpc.CallOption) (outputReceiver, error)

func doOutput(ctx context.Context, handle string, streaming bool, f receiverFunc) error {
	stream, err := f(ctx, &pb.OutputRequest{Id: &pb.ProcessHandle{Value: handle}, Stream: streaming})
	if err != nil {
		return fmt.Errorf("error getting output stream: %v", err)
	}

	var s *pb.ProcessOutput
	for err != io.EOF {
		s, err = stream.Recv()
		if err != nil && err != io.EOF {
			return err
		}
		if _, writeErr := os.Stdout.Write(s.GetValue()); writeErr != nil {
			return writeErr

		}
	}
	return nil
}
