package cmd

import (
	"fmt"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:          "status [process ID]",
	Short:        "Query process status",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := client.Status(cmd.Context(), &pb.ProcessHandle{Value: args[0]})
		if err != nil {
			return err
		}

		fmt.Printf("Status for process %s: %s\n", args[0], status.GetState().String())
		switch status.State {
		case pb.ProcessStatus_EXITED, pb.ProcessStatus_STOPPED:
			fmt.Printf("Exit code: %d; Error message: %s\n", status.GetExitCode(), status.GetExitError())
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
