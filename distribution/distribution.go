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
	"strings"

	"github.com/h2non/filetype"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
	"github.com/xi2/xz"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

var qcowType = filetype.NewType("qcow2", "qcow2/qcow2")

func qcow2Matcher(buf []byte) bool {
	return len(buf) > 1 && buf[0] == 0x51 && buf[1] == 0x46 && buf[2] == 0x49 && buf[3] == 0xfb
}

func init() {
	filetype.AddMatcher(qcowType, qcow2Matcher)
}

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

func (d *Distribution) Get() error {
	distroList := []*Distribution{}
	existingDistros, err := d.List()
	if err != nil {
		return err
	}
	if d.Type != "" || d.Name != "" {
		for _, distro := range existingDistros {
			if distro.Type == d.Type {
				if d.Name != "" {
					if distro.Name == d.Name {
						distroList = append(distroList, distro)
					} else {
						distroList = append(distroList, distro)
					}
				}
			}
		}
	} else {
		distroList = existingDistros
	}
	d.Print(distroList)
	return nil
}

func (d *Distribution) Print(distroList []*Distribution) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"DISTRIBUTION", "NAME", "IMAGE"})
	tableRows := []table.Row{}
	for _, distro := range distroList {
		tableRows = append(tableRows, table.Row{distro.Type, distro.Name, filepath.Base(distro.Image.ImageURL)})
	}
	t.AppendRows(tableRows)
	t.Render()
}

func (d *Distribution) List() ([]*Distribution, error) {
	distroList := []*Distribution{}
	distros, err := ioutil.ReadDir(d.Environment.ImagePath)
	if err != nil {
		return nil, err
	}
	for _, dir := range distros {
		if dir.IsDir() {
			distro, err := ioutil.ReadDir(d.Environment.ImagePath + "/" + dir.Name())
			if err != nil {
				return nil, err
			}
			for _, distroDir := range distro {
				if distroDir.IsDir() {
					imageByte, err := os.ReadFile(d.Environment.ImagePath + "/" + dir.Name() + "/" + distroDir.Name() + "/image.yaml")
					if err != nil {
						return nil, err
					}
					img := &image.Image{}
					if err := yaml.Unmarshal(imageByte, img); err != nil {
						return nil, err
					}
					dis := &Distribution{
						Name:  distroDir.Name(),
						Type:  DistributionType(dir.Name()),
						Image: img,
					}
					distroList = append(distroList, dis)
				}
			}

		}
	}
	return distroList, nil
}

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

	rootFSExists, err := d.RootfsImageExists(distroPath)
	if err != nil {
		return err
	}
	if !rootFSExists {
		imageFileExists, err := FileDirectoryExists(distroPath + "/" + filepath.Base(distroImage.ImageURL))
		if err != nil {
			return err
		}
		if !imageFileExists {
			if err := DistributionDownload(distroImage.ImageURL, distroPath); err != nil {
				return err
			}
		}
		if err := d.ExtractImage(distroImage, distroPath); err != nil {
			return err
		}
	}

	kernelImageExists, err := KernelImageExists(distroPath)
	if err != nil {
		return err
	}

	initrdImageExists, err := InitrdExists(distroPath)
	if err != nil {
		return err
	}

	if !kernelImageExists || !initrdImageExists {
		if err := d.ExtractKernelInitrd(distroPath); err != nil {
			return err
		}
	}
	if err := CreateYAML(distroImage, di.GetDefaultUser(), distroPath); err != nil {
		return err
	}

	if err := chownR(filepath.Dir(distroPath), os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	return nil
}

func CreateYAML(img *image.Image, defaultUser, distroPath string) error {
	img.DefaultUser = defaultUser
	imageYaml, err := yaml.Marshal(img)
	if err != nil {
		return err
	}
	if err := os.WriteFile(distroPath+"/image.yaml", imageYaml, 0660); err != nil {
		return err
	}
	return nil
}

func (d *Distribution) ExtractKernelInitrd(distroPath string) error {
	cmd := []string{
		"--unversioned-names", "-a", "/disk/" + d.Image.Rootfs,
	}
	log.Infof("extracting initrd and kernel image from %s/%s\n", distroPath, d.Image.Rootfs)
	out, err := DockerRun(cmd, []string{"virt-get-kernel"}, distroPath)
	if err != nil {
		return err
	}
	var names []string
	for _, line := range out {
		if line != "" {
			newLine := strings.SplitAfter(line, "-> ./")
			if len(newLine) > 0 {
				names = append(names, strings.TrimSuffix(newLine[1], "\r"))
			}
		}
	}
	if len(names) != 2 {
		return fmt.Errorf("could extract kernel/initrd image")
	}
	if err := os.Rename(distroPath+"/"+names[0], distroPath+"/vmlinuz"); err != nil {
		return err
	}
	if err := os.Rename(distroPath+"/"+names[1], distroPath+"/initrd"); err != nil {
		return err
	}
	d.Image.Kernel = "vmlinuz"
	d.Image.Initrd = "initrd"
	return nil
}

func (d *Distribution) DistributionExists(di DistributionInterface, distroPath string) (bool, error) {
	kernelImageExists, err := KernelImageExists(distroPath)
	if err != nil {
		return false, err
	}
	if !kernelImageExists {
		return false, nil
	}

	rootfsImageExists, err := d.RootfsImageExists(distroPath)
	if err != nil {
		return false, err
	}
	if !rootfsImageExists {
		return false, nil
	}

	initrdImageExists, err := InitrdExists(distroPath)
	if err != nil {
		return false, err
	}
	if !initrdImageExists {
		return false, nil
	}

	return true, nil
}

func KernelImageExists(distributionPath string) (bool, error) {
	return FileDirectoryExists(distributionPath + "/vmlinuz")
}

func (d *Distribution) RootfsImageExists(distributionPath string) (bool, error) {
	rawExists, err := FileDirectoryExists(distributionPath + "/disk.raw")
	if err != nil {
		return false, err
	}
	qcowExists, err := FileDirectoryExists(distributionPath + "/disk.qcow")
	if err != nil {
		return false, err
	}
	if !rawExists && !qcowExists {
		return false, nil
	}
	if rawExists {
		d.Image.Rootfs = "disk.raw"
	}
	if qcowExists {
		d.Image.Rootfs = "disk.qcow"
	}
	return true, nil
}

func InitrdExists(distributionPath string) (bool, error) {
	return FileDirectoryExists(distributionPath + "/initrd")
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

func DistributionDownload(url string, path string) error {
	log.Infof("downloading image %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("cannot download %d\n", resp.StatusCode)
	}

	// Create the file
	out, err := os.Create(path + "/" + filepath.Base(url))
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return nil
}

func (d *Distribution) ExtractImage(img *image.Image, distroPath string) error {
	log.Println("extracting rootfs")
	buf, _ := ioutil.ReadFile(distroPath + "/" + filepath.Base(img.ImageURL))
	kind, _ := filetype.Match(buf)
	if kind == filetype.Unknown {
		return errors.New("Unknown file type")
	}
	fmt.Printf("%x\n", buf[0:4])
	switch kind.Extension {
	case "xz":
		if err := extractXZ(distroPath, filepath.Base(img.ImageURL)); err != nil {
			return err
		}
		d.Image.Rootfs = "disk.raw"
		d.Image.ImageFormat = string(image.RAW)
	case "qcow2":
		if err := convertToRaw(filepath.Base(img.ImageURL), distroPath); err != nil {
			return err
		}
		//os.Rename(distroPath+"/"+filepath.Base(img.ImageURL), distroPath+"/"+"disk.qcow2")
		d.Image.Rootfs = "disk.raw"
		d.Image.ImageFormat = string(image.QCOW2)
	}
	return nil
}

func convertToRaw(image, distroPath string) error {
	convertRawArgs := []string{
		"convert", "/disk/" + image, "/disk/disk.raw",
	}
	if _, err := DockerRun(convertRawArgs, []string{"qemu-img"}, distroPath); err != nil {
		return err
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
			os.Rename(path+"/"+hdr.Name, path+"/disk.raw")
		}
	}
	f.Close()
	return err
}

func chownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}
