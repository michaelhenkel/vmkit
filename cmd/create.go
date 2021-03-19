package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.AddCommand(createDistributionCmd)
	/*
		createCmd.Flags().StringVarP(&name, "name", "n", "", "-name")
		createCmd.Flags().StringVarP(&distro, "distribution", "d", "Debian", "-ds")
		createCmd.MarkFlagRequired("name")
	*/
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "creates a virtual machine",
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

func createInitConfig() {
	if name == "" {
		log.Println("name is missing")
		os.Exit(1)
	}
}
