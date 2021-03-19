package cmd

import (
	"os"

	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/instance"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	distro string
)

func init() {
	log.SetReportCaller(true)
	createDistributionCmd.Flags().StringVarP(&name, "name", "n", "", "-name")
	createDistributionCmd.Flags().StringVarP(&distro, "distribution", "d", "Debian", "-ds")
	createDistributionCmd.MarkFlagRequired("name")
}

var createDistributionCmd = &cobra.Command{
	Use:   "distribution",
	Short: "creates a distribution",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		env, err := environment.Create()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		var dI distribution.DistributionInterface

		switch distribution.Distribution(distro) {
		case distribution.DebianDist:
			dI = &distribution.Debian{
				Environment: env,
			}
		}

		if err := distribution.Create(dI, env); err != nil {
			return
		}

		inst := &instance.Instance{
			Name:         name,
			Distribution: distribution.Distribution(distro),
		}

		if err := inst.Setup(); err != nil {
			log.Println(err)
			os.Exit(1)
		}

	},
}
