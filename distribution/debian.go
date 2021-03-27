package distribution

import (
	"github.com/michaelhenkel/vmkit/image"
)

type Debian struct {
	*Distribution
}

func (d *Debian) DefaultDistribution() *Debian {
	d.Distribution.Image = &image.Image{
		ImageURL:    "https://cloud.debian.org/images/cloud/buster/daily/20210316-578/debian-10-generic-amd64-daily-20210316-578.tar.xz",
		DefaultUser: "debian",
		ImageFormat: "raw",
	}
	return d
}

func (d *Debian) GetImage() *image.Image {
	d.Distribution.Type = DebianDist
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
