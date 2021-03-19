package cmd

import (
	"os"

	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	distroType string
	distroFile string
)

func init() {
	log.SetReportCaller(true)
	createDistributionCmd.Flags().StringVarP(&name, "name", "n", "", "-name")
	createDistributionCmd.Flags().StringVarP(&distroType, "type", "t", "Debian", "distribution type")
	createDistributionCmd.Flags().StringVarP(&distroFile, "file", "f", "", "distribution file")
	createDistributionCmd.MarkFlagRequired("name")
	createDistributionCmd.MarkFlagRequired("type")
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
		distro := &distribution.Distribution{
			Name:        name,
			Environment: env,
		}
		if distroFile != "" {
			distroYaml, err := os.ReadFile(distroFile)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
			if err := yaml.Unmarshal(distroYaml, distro); err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}

		var dI distribution.DistributionInterface
		switch distribution.DistributionType(distroType) {
		case distribution.DebianDist:
			debian := &distribution.Debian{}
			debian.Distribution = distro
			if distro.Image != nil {
				debian.Distribution.Image = distro.Image
			}
			dI = debian
		}

		if err := distribution.Create(dI, env); err != nil {
			return
		}
	},
}
