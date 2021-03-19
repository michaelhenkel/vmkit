package cmd

import (
	"os"

	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/instance"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	log.SetReportCaller(true)
	createCmd.AddCommand(createInstanceCmd)
	createInstanceCmd.Flags().StringVarP(&name, "name", "n", "", "-name of the instance")
	createInstanceCmd.Flags().StringVarP(&distroType, "type", "t", "Debian", "type of the distribution")
	createInstanceCmd.Flags().IntVarP(&cpu, "cpu", "c", 2, "number of cpus")
	createInstanceCmd.Flags().IntVarP(&memory, "memory", "m", 2048, "amount of memory")
	createInstanceCmd.MarkFlagRequired("name")
	deleteInstanceCmd.Flags().StringVarP(&name, "name", "n", "", "-name of the instance")
	deleteInstanceCmd.MarkFlagRequired("name")
}

var (
	cpu    int
	memory int
)

var createInstanceCmd = &cobra.Command{
	Use:   "instance",
	Short: "creates an instance",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		inst := &instance.Instance{
			Name:         name,
			Distribution: distribution.DistributionType(distroType),
			CPU:          cpu,
			Memory:       memory,
		}

		if err := inst.Setup(); err != nil {
			log.Println(err)
			os.Exit(1)
		}

	},
}

var deleteInstanceCmd = &cobra.Command{
	Use:   "instance",
	Short: "deletes an instance",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		inst := &instance.Instance{
			Name: name,
		}

		if err := inst.Delete(); err != nil {
			log.Println(err)
			os.Exit(1)
		}

	},
}
