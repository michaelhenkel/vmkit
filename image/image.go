package image

type Distribution string
type Format string

const (
	XZ  Format = "xz"
	IMG Format = "img"
	RAW Format = "raw"
)

type Image struct {
	Rootfs       string
	Kernel       string
	Initrd       string
	ImageURL     string
	RootfsFormat Format
	ImageFile    string
	FSLabel      string
}

// CreateImage creates an image
func CreateImage(distribution string) {

}
