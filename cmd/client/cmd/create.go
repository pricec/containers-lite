package cmd

import (
	"fmt"

	"github.com/pricec/containers-lite/pb"
	"github.com/spf13/cobra"
)

var (
	limits pb.ResourceLimits

	createCmd = &cobra.Command{
		Use:          "create -- [command] [argument...]",
		Short:        "Create a process",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			processID, err := client.Create(
				cmd.Context(),
				&pb.LaunchConfiguration{
					Command: args[0],
					Args:    args[1:],
					Limits:  &limits,
				},
			)

			if err != nil {
				return fmt.Errorf("error creating process: %v", err)
			}

			fmt.Println(processID.GetValue())
			return nil
		},
	}
)

func init() {
	createCmd.Flags().Uint32Var(&limits.MemoryInMib, "memory", 64, "process memory limit (in MiB)")
	createCmd.Flags().Uint32Var(&limits.CpuMillicores, "millicores", 100, "CPU millicores limit (1000 millicores = 1 core)")
	createCmd.Flags().Uint32Var(&limits.DiskReadMbps, "disk-read", 10, "disk read limit in MBPS")
	createCmd.Flags().Uint32Var(&limits.DiskWriteMbps, "disk-write", 10, "disk write limit in MBPS")

	rootCmd.AddCommand(createCmd)
}
