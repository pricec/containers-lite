package cmd

import (
	"context"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	stream bool

	outputCmd = &cobra.Command{
		Use:          "output [process ID]",
		Short:        "View process output",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doOutput(cmd.Context(), args[0], stream, func(ctx context.Context, req *pb.OutputRequest, opts ...grpc.CallOption) (outputReceiver, error) {
				stream, err := client.Output(ctx, req, opts...)
				return stream, err
			})
		},
	}
)

func init() {
	outputCmd.Flags().BoolVar(&stream, "stream", false, "stream output")
	rootCmd.AddCommand(outputCmd)
}
