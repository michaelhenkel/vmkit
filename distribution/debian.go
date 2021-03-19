package distribution

import (
	"fmt"

	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
)

type Debian struct {
	Environment *environment.Environment
	Image       image.Image
}

var DefaultDebian = &Debian{
	Image: image.Image{
		Rootfs:       "disk.raw",
		Kernel:       "vmlinuz-4.19.0-14-amd64",
		Initrd:       "initrd.img-4.19.0-14-amd64",
		ImageURL:     "https://cloud.debian.org/images/cloud/buster/daily/20210316-578",
		ImageFile:    "debian-10-generic-amd64-daily-20210316-578.tar.xz",
		RootfsFormat: image.XZ,
		FSLabel:      "root=UUID=e2964738-3c8b-4a26-8b61-8044940ae6c1",
	},
}

func (d *Debian) GetImage() *image.Image {
	return &DefaultDebian.Image
}

func (d *Debian) GetDefaultUser() string {
	return "debian"
}

func (d *Debian) GetDistribution() Distribution {
	return DebianDist
}

func (d *Debian) Create() error {
	d.Image = DefaultDebian.Image
	return nil
}

func (d *Debian) CreateImages(img *image.Image) error {
	distroPath := fmt.Sprintf("%s/Debian", d.Environment.BasePath)
	kernelImageExists, err := KernelImageExists(distroPath, img)
	if err != nil {
		return err
	}
	if !kernelImageExists {
		getKernelCmd := []string{
			"--ro", "-a", "/disk/disk.raw", "-i", "copy-out", "/boot/vmlinuz-4.19.0-14-amd64", "/disk",
		}
		if err := DockerRun(getKernelCmd, nil, distroPath); err != nil {
			return err
		}
	}
	initrdExists, err := InitrdExists(distroPath, img)
	if err != nil {
		return err
	}
	if !initrdExists {
		getInitrdCmd := []string{
			"--ro", "-a", "/disk/disk.raw", "-i", "copy-out", "/boot/initrd.img-4.19.0-14-amd64", "/disk",
		}
		if err := DockerRun(getInitrdCmd, nil, distroPath); err != nil {
			return err
		}
	}
	return nil
}
