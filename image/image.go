package image

type Distribution string
type Format string

const (
	XZ  Format = "xz"
	IMG Format = "img"
	RAW Format = "raw"
)

type Image struct {
	Rootfs        string `yaml:"rootfs"`
	Kernel        string `yaml:"kernel"`
	Initrd        string `yaml:"initrd"`
	ImageURL      string `yaml:"imageURL"`
	ImageFile     string `yaml:"imageFile"`
	BootPartition string `yaml:"bootPartition"`
	FSLabel       string `yaml:"fsLabel"`
	DefaultUser   string `yaml:"defaultUser"`
}
