package distribution

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
	"github.com/xi2/xz"
)

type Distribution string

type DistributionInterface interface {
	Create() error
	GetImage() *image.Image
	GetDistribution() Distribution
	CreateImages(*image.Image) error
	GetDefaultUser() string
}

const (
	UbuntuDist Distribution = "Ubuntu"
	DebianDist Distribution = "Debian"
	CustomDist Distribution = "Custom"
	CentosDist Distribution = "Centos"
	RedhatDist Distribution = "Redhat"
	FedoraDist Distribution = "Fedora"
)

func Create(di DistributionInterface, env *environment.Environment) error {
	distroImage := di.GetImage()
	distro := di.GetDistribution()
	distroPath := fmt.Sprintf("%s/%s", env.BasePath, distro)
	_, err := DistributionDirectoryExists(distroPath, distroImage)
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

	if err := di.CreateImages(distroImage); err != nil {
		return err
	}
	return nil
}

func DistributionExists(di DistributionInterface, env *environment.Environment) (bool, error) {
	distro := di.GetDistribution()
	distroPath := fmt.Sprintf("%s/%s", env.BasePath, distro)
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

func DistributionDirectoryExists(distributionPath string, img *image.Image) (bool, error) {
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
	switch img.RootfsFormat {
	case image.XZ:
		if err := extractXZ(distroPath, img.ImageFile); err != nil {
			return err
		}
	}
	return nil
}

func extractXZ(path string, xzFile string) error {
	log.Println(xzFile)
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
			fmt.Println("extracting: " + path + "/" + hdr.Name)
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
