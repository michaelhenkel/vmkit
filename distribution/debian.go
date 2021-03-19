package distribution

import (
	"github.com/michaelhenkel/vmkit/image"
)

type Debian struct {
	*Distribution
}

func (d *Debian) DefaultDistribution() *Debian {
	d.Distribution.Image = &image.Image{
		Rootfs:       "disk.raw",
		Kernel:       "vmlinuz-4.19.0-14-amd64",
		Initrd:       "initrd.img-4.19.0-14-amd64",
		ImageURL:     "https://cloud.debian.org/images/cloud/buster/daily/20210316-578",
		ImageFile:    "debian-10-generic-amd64-daily-20210316-578.tar.xz",
		RootfsFormat: image.XZ,
		FSLabel:      "root=UUID=e2964738-3c8b-4a26-8b61-8044940ae6c1",
	}
	return d
}

func (d *Debian) GetImage() *image.Image {
	if d.Image == nil {
		return d.DefaultDistribution().Image
	}
	return d.Image
}

func (d *Debian) GetDefaultUser() string {
	return "debian"
}

func (d *Debian) GetName() string {
	return d.Name
}

func (d *Debian) GetDistribution() DistributionType {
	return DebianDist
}

func (d *Debian) CreateImages(img *image.Image, distroPath string) error {
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
