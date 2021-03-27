package image

type Distribution string
type Format string

const (
	XZ    Format = "xz"
	IMG   Format = "img"
	RAW   Format = "raw"
	QCOW2 Format = "qcow2"
)

type Image struct {
	ImageURL    string `yaml:"imageURL"`
	DefaultUser string `yaml:"defaultUser"`
	ImageFormat string `yaml:"imageFormat"`
	Rootfs      string `yaml:"rootfs"`
	Initrd      string `yaml:"initrd"`
	Kernel      string `yaml:"kernel"`
}
