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
	distroImage string
	distroURL   string
)

func init() {
	createDistributionCmd.Flags().StringVarP(&distroImage, "image", "i", "", "distribution image file")
	createDistributionCmd.Flags().StringVarP(&distroURL, "url", "u", "", "distribution image url")
	createDistributionCmd.MarkFlagRequired("type")
}

var createDistributionCmd = &cobra.Command{
	Use:   "distribution",
	Short: "creates a distribution",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if name != "" {
			if distroType == "" && (distroImage == "" && distroURL == "") {
				fmt.Println("with name a distro type and distro image file or url file must be specified")
				os.Exit(1)
			}
		}
		if name == "" && (distroImage != "" || distroURL != "") {
			fmt.Println("with distro image file or url, a name must be specified")
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

		if distroURL != "" {
			img := &image.Image{
				ImageURL: distroURL,
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
		case distribution.CentosDist:
			centos := &distribution.Centos{}
			centos.Distribution = distro
			if distro.Image != nil {
				centos.Distribution.Image = distro.Image
			}
			dI = centos
		}

		if err := distro.Create(dI, env); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	},
}

var getDistributionCmd = &cobra.Command{
	Use:   "distribution",
	Short: "gets a distribution",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		env, err := environment.Create()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		distro := &distribution.Distribution{
			Environment: env,
		}
		if distroType != "" {
			distro.Type = distribution.DistributionType(distroType)
		}
		if name != "" {
			distro.Name = name
		}
		if err := distro.Get(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	},
}
