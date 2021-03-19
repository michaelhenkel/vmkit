package cmd

import (
	"fmt"
	"os"

	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	distroType  string
	distroImage string
)

func init() {
	createDistributionCmd.Flags().StringVarP(&name, "name", "n", "default", "-name")
	createDistributionCmd.Flags().StringVarP(&distroType, "type", "t", "Debian", "distribution type")
	createDistributionCmd.Flags().StringVarP(&distroImage, "image", "i", "", "distribution image file")
	createDistributionCmd.MarkFlagRequired("type")
}

var createDistributionCmd = &cobra.Command{
	Use:   "distribution",
	Short: "creates a distribution",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if name != "" && (distroType == "" || distroImage == "") {
			fmt.Println("with name a distro type and distro image file must be specified")
			os.Exit(1)
		}
		if name == "" && distroImage != "" {
			fmt.Println("with distro image file, a name must be specified")
			os.Exit(1)
		}
		if name == "" {
			name = "default"
		}

		env, err := environment.Create()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		distro := &distribution.Distribution{
			Name:        name,
			Environment: env,
			Type:        distribution.DistributionType(distroType),
		}
		if distroImage != "" {
			img := &image.Image{}
			distroImageYaml, err := os.ReadFile(distroImage)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
			if err := yaml.Unmarshal(distroImageYaml, img); err != nil {
				log.Println(err)
				os.Exit(1)
			}
			distro.Image = img
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

		if err := distro.Create(dI, env); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	},
}
