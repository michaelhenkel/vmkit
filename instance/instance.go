package instance

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/machine/libmachine/state"
	"github.com/kdomanski/iso9660"
	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/image"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	ps "github.com/mitchellh/go-ps"
	hyperkit "github.com/moby/hyperkit/go"
	vmnet "github.com/zchee/go-vmnet"
	yaml "gopkg.in/yaml.v2"
)

type InstanceInterface interface {
	Create() error
}

const (
	permErr = "%s needs to run with elevated permissions. " +
		"Please run the following command, then try again: " +
		"sudo chown root:wheel %s && sudo chmod u+s %s"
)

type Instance struct {
	Name         string
	Directory    string
	PidFile      string
	Distribution distribution.DistributionType
	Environmnet  *environment.Environment
	Image        *image.Image
	IPAddress    string
	CmdLine      string
	UUID         string
	CPU          int
	Memory       int
}

func init() {
	//log.SetReportCaller(true)
	//log.SetLevel(log.InfoLevel)
	hyperkit.SetLogger(&logrus.Logger{Level: logrus.Level(1)})
}

func (i *Instance) Setup() error {

	if err := verifyRootPermissions(); err != nil {
		return err
	}
	usr, err := user.Current()
	if err != nil {
		return err
	}
	directory := fmt.Sprintf("%s/.vmkit/%s", usr.HomeDir, i.Name)
	i.Directory = directory
	i.PidFile = directory + "/hyperkit.pid"

	env, err := environment.Create()
	if err != nil {
		return err
	}
	i.Environmnet = env

	var dI distribution.DistributionInterface

	switch distribution.DistributionType(i.Distribution) {
	case distribution.DebianDist:
		distro := &distribution.Debian{}
		distro.Environment = env
		dI = distro
	}

	i.Image = dI.GetImage()
	distExists, err := distribution.DistributionExists(dI, env.BasePath+"/"+string(i.Distribution)+"/"+dI.GetName())
	if !distExists {
		return errors.New("distribution doesn't exist")
	}

	envExists, err := i.exists()
	if err != nil {
		return err
	}
	if !envExists {
		if err := i.createEnvironment(); err != nil {
			return err
		}
	} else {
		isActive, err := i.active()
		if err != nil {
			return err
		}
		if isActive {
			return fmt.Errorf("instance is already active")
		}
	}
	i.UUID = uuid.NewUUID().String()
	i.CmdLine = i.Image.FSLabel + " loglevel=3 console=ttyS0 console=tty0 noembed nomodeset norestore waitusb=10 systemd.legacy_systemd_cgroup_controller=yes random.trust_cpu=on hw_rng_model=virtio base host=" + i.Name
	if err := i.create(dI); err != nil {
		return err
	}
	return nil
}

func (i *Instance) create(dI distribution.DistributionInterface) error {
	initrd := dI.GetImage().Initrd
	kernel := dI.GetImage().Kernel
	rootfs := dI.GetImage().Rootfs

	distroPath := i.Environmnet.BasePath + "/" + string(i.Distribution) + "/" + dI.GetName()
	rootfsExists, err := distribution.FileDirectoryExists(i.Directory + "/" + rootfs)
	if err != nil {
		return err
	}
	if !rootfsExists {
		if err := copy(distroPath+"/"+rootfs, i.Directory+"/"+rootfs); err != nil {
			return err
		}
	}

	kernelExists, err := distribution.FileDirectoryExists(i.Directory + "/" + kernel)
	if err != nil {
		return err
	}
	if !kernelExists {
		if err := copy(distroPath+"/"+kernel, i.Directory+"/"+kernel); err != nil {
			return err
		}
	}

	initrdExists, err := distribution.FileDirectoryExists(i.Directory + "/" + initrd)
	if err != nil {
		return err
	}
	if !initrdExists {
		if err := copy(distroPath+"/"+initrd, i.Directory+"/"+initrd); err != nil {
			return err
		}
	}

	cloudInitExists, err := distribution.FileDirectoryExists(i.Directory + "/cidata.iso")
	if err != nil {
		return err
	}
	if !cloudInitExists {
		if err := i.createCloudInit(); err != nil {
			return err
		}

		if err := i.createISO(); err != nil {
			return err
		}
	}

	h, err := i.createInstance()
	if err != nil {
		return err
	}

	mac, err := GetMACAddressFromUUID(i.UUID)
	if err != nil {
		return err
	}

	// Need to strip 0's
	mac = trimMacAddress(mac)

	_, err = h.Start(i.CmdLine)
	if err != nil {
		return err
	}

	if err := i.setupIP(mac); err != nil {
		return err
	}

	if err := chownR(i.Directory, os.Getuid(), os.Getgid()); err != nil {
		return err
	}

	ttyByte, err := os.ReadFile(i.Directory + "/tty")
	if err != nil {
		return err
	}
	if err := chownR(string(ttyByte), os.Getuid(), os.Getgid()); err != nil {
		return err
	}

	fmt.Printf("ssh -i %s %s@%s\n", i.Directory+"/id_rsa", dI.GetDefaultUser(), i.IPAddress)

	return nil
}

func chownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}

type tempError struct {
	Err error
}

func GetMACAddressFromUUID(id string) (string, error) {
	return vmnet.GetMACAddressFromUUID(id)
}

func (t tempError) Error() string {
	return "Temporary error: " + t.Err.Error()
}

func (i *Instance) createInstance() (*hyperkit.HyperKit, error) {
	h, err := hyperkit.New("", "", i.Directory)
	if err != nil {
		return nil, err
	}

	h.Kernel = i.Directory + "/" + i.Image.Kernel
	h.Initrd = i.Directory + "/" + i.Image.Initrd
	h.VMNet = true
	h.ISOImages = []string{i.Directory + "/cidata.iso"}
	h.Console = hyperkit.ConsoleFile
	h.CPUs = i.CPU
	h.Memory = i.Memory
	h.UUID = i.UUID

	/*
		if vsockPorts, err := d.extractVSockPorts(); err != nil {
			return nil, err
		} else if len(vsockPorts) >= 1 {
			h.VSock = true
			h.VSockPorts = vsockPorts
		}
	*/

	h.Disks = []hyperkit.Disk{
		&hyperkit.RawDisk{
			Path: i.Directory + "/" + i.Image.Rootfs,
			Size: 2048,
			Trim: true,
		},
	}

	return h, err
}

func (i *Instance) setupIP(mac string) error {
	getIP := func() error {
		st, err := i.GetState()
		if err != nil {
			return err
		}
		if st == state.Error || st == state.Stopped {
			return fmt.Errorf("hyperkit crashed! command line:\n  hyperkit %s", i.CmdLine)
		}

		i.IPAddress, err = GetIPAddressByMACAddress(mac)
		if err != nil {
			return &tempError{err}
		}
		return nil
	}

	var err error

	// Implement a retry loop without calling any minikube code
	for i := 0; i < 30; i++ {
		err = getIP()
		if err == nil {
			break
		}
		if _, ok := err.(*tempError); !ok {
			return err
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("IP address never found in dhcp leases file %v", err)
	}

	return nil
}

func (i *Instance) GetState() (state.State, error) {
	pid := i.getPid()
	return pidState(pid)
}

// Return the state of the hyperkit pid
func pidState(pid int) (state.State, error) {
	if pid == 0 {
		return state.Stopped, nil
	}
	p, err := ps.FindProcess(pid)
	if err != nil {
		return state.Error, err
	}
	if p == nil {
		return state.Stopped, nil
	}
	// hyperkit or com.docker.hyper
	if !strings.Contains(p.Executable(), "hyper") {
		return state.Stopped, nil
	}
	return state.Running, nil
}

func verifyRootPermissions() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	euid := syscall.Geteuid()
	if euid != 0 {
		return fmt.Errorf(permErr, filepath.Base(exe), exe, exe)
	}
	return nil
}

type userData struct {
	Password string `yaml:"password"`
	Chpasswd struct {
		Expire bool `yaml:"expire"`
	} `yaml:"chpasswd"`
	SshPwauth         bool     `yaml:"ssh_pwauth"`
	SshAuthorizedKeys []string `yaml:"ssh_authorized_keys"`
	Users             []string `yaml:"users"`
}

type metaData struct {
	InstanceId    string `yaml:"instance-id"`
	LocalHostname string `yaml:"local-hostname"`
}

func (i *Instance) createCloudInit() error {
	privateKeyExists, err := distribution.FileDirectoryExists(i.Directory + "/private.pem")
	if err != nil {
		return err
	}
	publicKeyExists, err := distribution.FileDirectoryExists(i.Directory + "/public.pem")
	if err != nil {
		return err
	}
	if !privateKeyExists || publicKeyExists {
		if err := i.generateKeys(); err != nil {
			return err
		}
	}

	publicKey, err := os.ReadFile(i.Directory + "/id_rsa.pub")
	if err != nil {
		return err
	}

	defaultUserData := &userData{
		Password: "default",
		Chpasswd: struct {
			Expire bool "yaml:\"expire\""
		}{false},
		SshPwauth:         true,
		Users:             []string{"default"},
		SshAuthorizedKeys: []string{string(publicKey)},
	}

	defaultMetaData := &metaData{
		InstanceId:    i.Name,
		LocalHostname: i.Name,
	}

	cloudInitPath := i.Directory + "/config"
	metaDataPath := cloudInitPath + "/meta-data"
	userDataPath := cloudInitPath + "/user-data"

	userDataYAML, err := yaml.Marshal(defaultUserData)
	if err != nil {
		return err
	}

	metaDataYAML, err := yaml.Marshal(*defaultMetaData)
	if err != nil {
		return err
	}

	userDataHeader := fmt.Sprintf("#cloud-config\n%s", string(userDataYAML))
	userDataOut := []byte(userDataHeader)

	if err := os.WriteFile(userDataPath, userDataOut, 0600); err != nil {
		return err
	}

	if err := os.WriteFile(metaDataPath, metaDataYAML, 0600); err != nil {
		return err
	}

	return nil
}

func (i *Instance) getPid() int {
	time.Sleep(time.Second * 3)

	pidByte, err := os.ReadFile(i.PidFile)
	if err != nil {
		return 0
	}
	pidInt, err := strconv.Atoi(string(pidByte))
	if err != nil {
		return 0
	}
	return pidInt
}

func (i *Instance) createISO() error {
	writer, err := iso9660.NewWriter()
	if err != nil {
		return err
	}
	defer writer.Cleanup()

	userData, err := os.Open(i.Directory + "/config/user-data")
	if err != nil {
		return err
	}
	defer userData.Close()

	err = writer.AddFile(userData, "user-data")
	if err != nil {
		return err
	}

	metaData, err := os.Open(i.Directory + "/config/meta-data")
	if err != nil {
		return err
	}
	defer metaData.Close()

	err = writer.AddFile(metaData, "meta-data")
	if err != nil {
		return err
	}

	outputFile, err := os.OpenFile(i.Directory+"/cidata.iso", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	err = writer.WriteTo(outputFile, "CIDATA")
	if err != nil {
		return err
	}

	err = outputFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func (i *Instance) generateKeys() error {
	savePrivateFileTo := i.Directory + "/id_rsa"
	savePublicFileTo := i.Directory + "/id_rsa.pub"
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		return err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		return err
	}

	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		return err
	}
	return nil
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func (i *Instance) exists() (bool, error) {
	if _, err := os.Stat(i.Directory + "/config"); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (i *Instance) createEnvironment() error {
	if err := os.MkdirAll(i.Directory+"/config", 0755); err != nil {
		return err
	}
	return nil
}

func (i *Instance) active() (bool, error) {
	if _, err := os.Stat(i.PidFile); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	pidByte, err := os.ReadFile(i.PidFile)
	if err != nil {
		return false, err
	}
	pidInt, err := strconv.Atoi(string(pidByte))
	if err != nil {
		return false, err
	}
	process, err := ps.FindProcess(pidInt)
	if err != nil {
		return false, err
	}
	if process == nil {
		return false, nil
	}
	return true, nil
}

const (
	// LeasesPath is the path to dhcpd leases
	LeasesPath = "/var/db/dhcpd_leases"
	// VMNetDomain is the domain for vmnet
	VMNetDomain = "/Library/Preferences/SystemConfiguration/com.apple.vmnet"
	// SharedNetAddrKey is the key for the network address
	SharedNetAddrKey = "Shared_Net_Address"
)

var (
	leadingZeroRegexp = regexp.MustCompile(`0([A-Fa-f0-9](:|$))`)
)

// DHCPEntry holds a parsed DNS entry
type DHCPEntry struct {
	Name      string
	IPAddress string
	HWAddress string
	ID        string
	Lease     string
}

// GetIPAddressByMACAddress gets the IP address of a MAC address
func GetIPAddressByMACAddress(mac string) (string, error) {
	return getIPAddressFromFile(mac, LeasesPath)
}

func getIPAddressFromFile(mac, path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	dhcpEntries, err := parseDHCPdLeasesFile(file)
	if err != nil {
		return "", err
	}
	for _, dhcpEntry := range dhcpEntries {
		if dhcpEntry.HWAddress == mac {
			return dhcpEntry.IPAddress, nil
		}
	}
	return "", fmt.Errorf("could not find an IP address for %s", mac)
}

func parseDHCPdLeasesFile(file io.Reader) ([]DHCPEntry, error) {
	var (
		dhcpEntry   *DHCPEntry
		dhcpEntries []DHCPEntry
	)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "{" {
			dhcpEntry = new(DHCPEntry)
			continue
		} else if line == "}" {
			dhcpEntries = append(dhcpEntries, *dhcpEntry)
			continue
		}

		split := strings.SplitN(line, "=", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid line in dhcp leases file: %s", line)
		}
		key, val := split[0], split[1]
		switch key {
		case "name":
			dhcpEntry.Name = val
		case "ip_address":
			dhcpEntry.IPAddress = val
		case "hw_address":
			// The mac addresses have a '1,' at the start.
			dhcpEntry.HWAddress = val[2:]
		case "identifier":
			dhcpEntry.ID = val
		case "lease":
			dhcpEntry.Lease = val
		default:
			return dhcpEntries, fmt.Errorf("unable to parse line: %s", line)
		}
	}
	return dhcpEntries, scanner.Err()
}

// trimMacAddress trimming "0" of the ten's digit
func trimMacAddress(rawUUID string) string {
	return leadingZeroRegexp.ReplaceAllString(rawUUID, "$1")
}

// GetNetAddr gets the network address for vmnet
func GetNetAddr() (net.IP, error) {
	plistPath := VMNetDomain + ".plist"
	if _, err := os.Stat(plistPath); err != nil {
		return nil, fmt.Errorf("stat: %v", err)
	}
	out, err := exec.Command("defaults", "read", VMNetDomain, SharedNetAddrKey).Output()
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(string(out)))
	if ip == nil {
		return nil, fmt.Errorf("could not get the network address for vmnet")
	}
	return ip, nil
}
