package distribution

import (
	"errors"
	"os"

	"github.com/michaelhenkel/vmkit/image"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

type Debian struct {
	*Distribution
}

func (d *Debian) DefaultDistribution() *Debian {
	d.Distribution.Image = &image.Image{
		Rootfs:        "disk.raw",
		Kernel:        "vmlinuz-4.19.0-14-amd64",
		Initrd:        "initrd.img-4.19.0-14-amd64",
		ImageURL:      "https://cloud.debian.org/images/cloud/buster/daily/20210316-578",
		ImageFile:     "debian-10-generic-amd64-daily-20210316-578.tar.xz",
		BootPartition: "/dev/sda1",
		DefaultUser:   "debian",
	}
	return d
}

func (d *Debian) GetImage() *image.Image {
	d.Distribution.Type = DebianDist
	if d.Image == nil {
		return d.DefaultDistribution().Image
	}
	if d.Image.BootPartition == "" {
		d.Image.BootPartition = "/dev/sda1"
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
			"--ro", "-a", "/disk/disk.raw", "-i", "copy-out", "/boot/" + img.Kernel, "/disk",
		}
		log.Infof("extracting kernel image %s/%s\n", distroPath, img.Kernel)
		if _, err := DockerRun(getKernelCmd, nil, distroPath); err != nil {
			return err
		}
	}
	initrdExists, err := InitrdExists(distroPath, img)
	if err != nil {
		return err
	}
	if !initrdExists {
		getInitrdCmd := []string{
			"--ro", "-a", "/disk/disk.raw", "-i", "copy-out", "/boot/" + img.Initrd, "/disk",
		}
		log.Infof("extracting initrd image %s/%s\n", distroPath, img.Initrd)
		if _, err := DockerRun(getInitrdCmd, nil, distroPath); err != nil {
			return err
		}
	}
	getFSLabelCmd := []string{
		"--ro", "-a", "/disk/disk.raw", "-i", "vfs-uuid", img.BootPartition,
	}
	log.Info("reading fs label")
	stdOut, err := DockerRun(getFSLabelCmd, nil, distroPath)
	if err != nil {
		return err
	}
	if stdOut == "" {
		return errors.New("cannot find fs label")
	}
	img.FSLabel = "root=UUID=" + stdOut
	img.DefaultUser = d.GetDefaultUser()
	imageYaml, err := yaml.Marshal(img)
	if err != nil {
		return err
	}
	if err := os.WriteFile(distroPath+"/image.yaml", imageYaml, 0660); err != nil {
		return err
	}
	return nil
}
