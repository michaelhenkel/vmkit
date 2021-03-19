package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetReportCaller(true)
	rootCmd.AddCommand(deleteCmd)
	deleteCmd.AddCommand(deleteInstanceCmd)
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "deletes a distribution or an instance",
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

func deleteInitConfig() {
	if name == "" {
		log.Println("name is missing")
		os.Exit(1)
	}
}
