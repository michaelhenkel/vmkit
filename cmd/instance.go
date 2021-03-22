package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/instance"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func init() {
	createCmd.AddCommand(createInstanceCmd)
	createInstanceCmd.Flags().StringVarP(&name, "name", "n", "", "-name of the instance")
	createInstanceCmd.Flags().StringVarP(&distroType, "type", "t", "Debian", "type of the distribution")
	createInstanceCmd.Flags().StringVarP(&distroName, "distro", "d", "default", "name of the distribution")
	createInstanceCmd.Flags().IntVarP(&cpu, "cpu", "c", 2, "number of cpus")
	createInstanceCmd.Flags().IntVarP(&scale, "scale", "s", 1, "number of instances")
	createInstanceCmd.Flags().IntVarP(&memory, "memory", "m", 2048, "amount of memory")
	createInstanceCmd.MarkFlagRequired("name")
	deleteInstanceCmd.Flags().StringVarP(&name, "name", "n", "", "-name of the instance")
	deleteInstanceCmd.MarkFlagRequired("name")
}

var (
	cpu    int
	memory int
	scale  int
)

var createInstanceCmd = &cobra.Command{
	Use:   "instance",
	Short: "creates an instance",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		resultSlice := []chan instance.Result{}
		distro := &distribution.Distribution{
			Type: distribution.DistributionType(distroType),
			Name: distroName,
		}
		env, err := environment.Create()
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		privateKeyExists, err := distribution.FileDirectoryExists(env.KeyPath + "/private.pem")
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		publicKeyExists, err := distribution.FileDirectoryExists(env.KeyPath + "/public.pem")
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		if !privateKeyExists || publicKeyExists {
			if err := generateKeys(env.KeyPath); err != nil {
				log.Error(err)
				os.Exit(1)
			}
		}
		for i := 0; i < scale; i++ {
			instanceName := name
			if scale > 1 {
				instanceName = name + "-" + strconv.Itoa(i)
			}
			ch := make(chan instance.Result)
			resultSlice = append(resultSlice, ch)
			inst := &instance.Instance{
				Name:         instanceName,
				Distribution: distro,
				CPU:          cpu,
				Memory:       memory,
				ResultCh:     ch,
			}
			log.Infof("creating instance %s", instanceName)
			go inst.Setup()
		}

		for _, ch := range resultSlice {
			for res := range ch {
				if res.Error == nil {
					log.Infof("ssh -o IdentitiesOnly=yes -i %s %s@%s\n", env.KeyPath+"/id_rsa", res.Instance.Distribution.Image.DefaultUser, res.Instance.IPAddress)
				} else {
					log.Errorf("Instance %s error %s", res.Instance.Name, res.Error)
				}
			}
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

func generateKeys(path string) error {
	savePrivateFileTo := path + "/id_rsa"
	savePublicFileTo := path + "/id_rsa.pub"
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		return err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		return err
	}

	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		return err
	}
	distribution.ChownR(filepath.Dir(path), os.Getuid(), os.Getgid())
	return nil
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
