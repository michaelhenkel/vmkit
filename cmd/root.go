package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "vmkit",
		Short: "vmkit manages virtual machines on hyperkit",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
		},
	}
)

func init() {
	rootCmd.AddCommand(createCmd, deleteCmd, getCmd)
	cobra.OnInitialize(initConfig)
}

func initConfig() {
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
