package distribution

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/h2non/filetype"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
	"github.com/xi2/xz"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

type DistributionType string

type Distribution struct {
	Environment *environment.Environment
	Image       *image.Image
	Type        DistributionType
	Name        string
}

type DistributionInterface interface {
	GetName() string
	GetImage() *image.Image
	GetDistribution() DistributionType
	CreateImages(*image.Image, string) error
	GetDefaultUser() string
}

const (
	UbuntuDist DistributionType = "Ubuntu"
	DebianDist DistributionType = "Debian"
	CustomDist DistributionType = "Custom"
	CentosDist DistributionType = "Centos"
	RedhatDist DistributionType = "Redhat"
	FedoraDist DistributionType = "Fedora"
)

func (d *Distribution) GetImage(env *environment.Environment) error {
	distroPath := fmt.Sprintf("%s/%s/%s", env.ImagePath, d.Type, d.Name)
	_, err := DistributionDirectoryExists(distroPath)
	if err != nil {
		return err
	}
	_, err = DistributionDirectoryExists(distroPath + "/image.yaml")
	if err != nil {
		return err
	}
	imageByte, err := os.ReadFile(distroPath + "/image.yaml")
	if err != nil {
		return err
	}
	img := &image.Image{}
	if err := yaml.Unmarshal(imageByte, img); err != nil {
		return err
	}
	d.Image = img

	return nil
}

func (d *Distribution) Create(di DistributionInterface, env *environment.Environment) error {
	distroImage := di.GetImage()
	distro := di.GetDistribution()
	distroPath := fmt.Sprintf("%s/%s/%s", env.ImagePath, distro, di.GetName())
	_, err := DistributionDirectoryExists(distroPath)
	if err != nil {
		return err
	}
	imageFileExists, err := FileDirectoryExists(distroPath + "/" + distroImage.ImageFile)
	if err != nil {
		return err
	}
	if !imageFileExists {
		if err := DistributionDownload(distroImage.ImageURL, distroImage.ImageFile, distroPath); err != nil {
			return err
		}
	}

	rootFSExists, err := RootfsImageExists(distroPath, distroImage)
	if err != nil {
		return err
	}
	if !rootFSExists {
		if err := ExtractImage(distroImage, distroPath); err != nil {
			return err
		}
	}

	if err := di.CreateImages(distroImage, distroPath); err != nil {
		return err
	}
	if err := chownR(filepath.Dir(distroPath), os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	return nil
}

func DistributionExists(di DistributionInterface, distroPath string) (bool, error) {
	img := di.GetImage()

	kernelImageExists, err := KernelImageExists(distroPath, img)
	if err != nil {
		return false, err
	}
	if !kernelImageExists {
		return false, nil
	}

	rootfsImageExists, err := RootfsImageExists(distroPath, img)
	if err != nil {
		return false, err
	}
	if !rootfsImageExists {
		return false, nil
	}

	initrdImageExists, err := InitrdExists(distroPath, img)
	if err != nil {
		return false, err
	}
	if !initrdImageExists {
		return false, nil
	}

	return true, nil
}

func KernelImageExists(distributionPath string, img *image.Image) (bool, error) {
	return FileDirectoryExists(distributionPath + "/" + img.Kernel)
}

func RootfsImageExists(distributionPath string, img *image.Image) (bool, error) {
	return FileDirectoryExists(distributionPath + "/" + img.Rootfs)
}

func InitrdExists(distributionPath string, img *image.Image) (bool, error) {
	return FileDirectoryExists(distributionPath + "/" + img.Initrd)
}

func DistributionDirectoryExists(distributionPath string) (bool, error) {
	dirExists, err := FileDirectoryExists(distributionPath)
	if err != nil {
		return false, err
	}
	if !dirExists {
		if err := FileDirectoryCreate(distributionPath); err != nil {
			return false, err
		}
	}
	return true, nil
}

func DistributionDownload(url string, file string, path string) error {
	log.Infof("downloading image %s\n", url+"/"+file)
	resp, err := http.Get(url + "/" + file)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(path + "/" + file)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return nil
}

func ExtractImage(img *image.Image, distroPath string) error {
	buf, _ := ioutil.ReadFile(distroPath + "/" + img.ImageFile)
	kind, _ := filetype.Match(buf)
	if kind == filetype.Unknown {
		return errors.New("Unknown file type")
	}
	switch kind.Extension {
	case "xz":
		if err := extractXZ(distroPath, img.ImageFile); err != nil {
			return err
		}
	}
	return nil
}

func extractXZ(path string, xzFile string) error {
	f, err := os.Open(path + "/" + xzFile)
	if err != nil {
		return err
	}
	// Create an xz Reader
	r, err := xz.NewReader(f, 0)
	if err != nil {
		return err
	}
	// Create a tar Reader
	tr := tar.NewReader(r)
	// Iterate through the files in the archive.
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			// create a directory
			fmt.Println("creating:   " + path + "/" + hdr.Name)
			err = os.MkdirAll(hdr.Name, 0777)
			if err != nil {
				return err
			}
		default:
			// write a file
			log.Info("extracting rootfs " + path + "/" + hdr.Name)
			w, err := os.Create(path + "/" + hdr.Name)
			if err != nil {
				return err
			}
			_, err = io.Copy(w, tr)
			if err != nil {
				return err
			}
			w.Close()
		}
	}
	f.Close()
	return nil
}

func chownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}
