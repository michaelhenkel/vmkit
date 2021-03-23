package distribution

import (
	"github.com/michaelhenkel/vmkit/image"
)

type Centos struct {
	*Distribution
}

func (d *Centos) DefaultDistribution() *Centos {
	d.Distribution.Image = &image.Image{
		Rootfs:        "CentOS-8-GenericCloud-8.3.2011-20201204.2.x86_64.raw",
		Kernel:        "vmlinuz",
		Initrd:        "initramfs",
		ImageURL:      "https://cloud.centos.org/centos/8/x86_64/images",
		ImageFile:     "CentOS-8-GenericCloud-8.3.2011-20201204.2.x86_64.qcow2",
		BootPartition: "/dev/sda1",
		DefaultUser:   "centos",
		ImageFormat:   "qcow2",
	}
	return d
}

func (d *Centos) GetImage() *image.Image {
	d.Distribution.Type = CentosDist
	if d.Image == nil {
		return d.DefaultDistribution().Image
	}
	if d.Image.BootPartition == "" {
		d.Image.BootPartition = "/dev/sda1"
	}
	return d.Image
}

func (d *Centos) GetDefaultUser() string {
	return "centos"
}

func (d *Centos) GetName() string {
	return d.Name
}

func (d *Centos) GetDistribution() DistributionType {
	return CentosDist
}
