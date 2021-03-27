package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func init() {
	//rootCmd.AddCommand(getCmd)
	getCmd.AddCommand(getDistributionCmd)
	getCmd.AddCommand(getInstanceCmd)
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "gets an instance or distribution",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a argument")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

	},
}
