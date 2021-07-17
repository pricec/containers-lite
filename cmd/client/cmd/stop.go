package cmd

import (
	"fmt"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:          "stop [process ID]",
	Short:        "Stop a process",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := client.Stop(cmd.Context(), &pb.ProcessHandle{Value: args[0]})
		if err == nil {
			fmt.Printf("Stopped process %s\n", args[0])
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
