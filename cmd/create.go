package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	name       string
	distroType string
)

func init() {
	createCmd.PersistentFlags().StringVarP(&name, "name", "n", "", "-name of the instance")
	createCmd.PersistentFlags().StringVarP(&distroType, "type", "t", "", "distribution type")
	createCmd.AddCommand(createDistributionCmd)
}

var createCmd = &cobra.Command{
	Use: "create",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a argument")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(name)
	},
}
