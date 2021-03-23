package instance

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
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
	"github.com/michaelhenkel/vmkit/vmnet"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"

	ps "github.com/mitchellh/go-ps"
	hyperkit "github.com/moby/hyperkit/go"
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
	Distribution *distribution.Distribution
	Environmnet  *environment.Environment
	IPAddress    string
	CmdLine      string
	UUID         string
	CPU          int
	Memory       int
	ResultCh     chan Result
}

type Result struct {
	Instance *Instance
	Error    error
}

func init() {
	hyperkit.SetLogger(&logrus.Logger{Level: logrus.Level(1)})
	rand.Seed(time.Now().UnixNano())
}

func (i *Instance) returnResult(err error) {
	r := Result{
		Instance: i,
		Error:    err,
	}
	i.ResultCh <- r
	close(i.ResultCh)
	return
}

func (i *Instance) Setup() {
	usr, err := user.Current()
	if err != nil {
		i.returnResult(err)
		return
	}
	directory := fmt.Sprintf("%s/.vmkit/instances/%s", usr.HomeDir, i.Name)
	i.Directory = directory
	i.PidFile = directory + "/hyperkit.pid"

	env, err := environment.Create()
	if err != nil {
		i.returnResult(err)
		return
	}
	i.Environmnet = env

	if err := i.Distribution.GetImage(env); err != nil {
		i.returnResult(err)
		return
	}

	envExists, err := i.exists()
	if err != nil {
		i.returnResult(err)
		return
	}
	if !envExists {
		if err := i.createEnvironment(); err != nil {
			i.returnResult(err)
			return
		}
	} else {
		isActive, err := i.active()
		if err != nil {
			i.returnResult(err)
			return
		}
		if isActive {
			i.returnResult(fmt.Errorf("instance is already active"))
			return
		}
	}
	i.UUID = uuid.NewUUID().String()
	//i.CmdLine = i.Distribution.Image.FSLabel + " loglevel=3 console=ttyS0 console=tty0 noembed nomodeset norestore waitusb=10 systemd.legacy_systemd_cgroup_controller=yes random.trust_cpu=on hw_rng_model=virtio base host=" + i.Name
	i.CmdLine = "earlyprintk=serial console=ttyS0 root=/dev/vda1 rw panic=1 no_timer_check base host=" + i.Name
	if err := i.create(); err != nil {
		i.returnResult(err)
		return
	}
	i.returnResult(nil)
	return
}

func (i *Instance) create() error {
	initrd := i.Distribution.Image.Initrd
	kernel := i.Distribution.Image.Kernel
	rootfs := i.Distribution.Image.Rootfs

	distroPath := i.Environmnet.ImagePath + "/" + string(i.Distribution.Type) + "/" + i.Distribution.Name
	rootfsExists, err := distribution.FileDirectoryExists(i.Directory + "/" + rootfs)
	if err != nil {
		return err
	}
	if !rootfsExists {
		if i.Distribution.Image.ImageFormat == string(image.QCOW2) {
			cmd := exec.Command("qemu-img", "convert", distroPath+"/"+i.Distribution.Image.ImageFile, i.Directory+"/"+i.Distribution.Image.Rootfs)
			if err := cmd.Run(); err != nil {
				return err
			}
		} else if err := copy(distroPath+"/"+rootfs, i.Directory+"/"+rootfs); err != nil {
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

	if err := verifyRootPermissions(); err != nil {
		return err
	}
	h, err := i.createInstance()
	if err != nil {
		return err
	}

	//mac, err := GetMACAddressFromUUID(i.UUID)

	mac, err := retryMacAddress(5, 1, GetMACAddressFromUUID, i.UUID)
	if err != nil {
		return err
	}

	// Need to strip 0's
	mac = trimMacAddress(mac)

	if err := retryStart(3, 1, hyperkitStart, h, i.CmdLine); err != nil {
		return err
	}
	/*
		_, err = h.Start(i.CmdLine)
		if err != nil {
			return err
		}
	*/

	if err := i.setupIP(mac); err != nil {
		return err
	}
	if err := chownR(filepath.Dir(i.Directory), os.Getuid(), os.Getgid()); err != nil {
		return err
	}

	ttyByte, err := os.ReadFile(i.Directory + "/tty")
	if err != nil {
		return err
	}
	if err := chownR(string(ttyByte), os.Getuid(), os.Getgid()); err != nil {
		return err
	}

	//fmt.Printf("ssh -o IdentitiesOnly=yes -i %s %s@%s\n", i.Directory+"/id_rsa", i.Distribution.Image.DefaultUser, i.IPAddress)

	return nil
}

func hyperkitStart(h *hyperkit.HyperKit, cmdline string) error {
	_, err := h.Start(cmdline)
	if err != nil {
		return err
	}
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

	h.Kernel = i.Directory + "/" + i.Distribution.Image.Kernel
	h.Initrd = i.Directory + "/" + i.Distribution.Image.Initrd
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
	var disk hyperkit.Disk
	disk = &hyperkit.RawDisk{
		Path: i.Directory + "/" + i.Distribution.Image.Rootfs,
		Size: 2048,
		Trim: true,
	}
	/*
		fmt.Println(i.Distribution.Image)
		switch i.Distribution.Image.ImageFormat {
		case string(image.QCOW2):
			disk = &hyperkit.QcowDisk{
				Path: i.Directory + "/" + i.Distribution.Image.Rootfs,
				Size: 2048,
				Trim: true,
			}
		case string(image.RAW):
			disk = &hyperkit.RawDisk{
				Path: i.Directory + "/" + i.Distribution.Image.Rootfs,
				Size: 2048,
				Trim: true,
			}
		}
	*/

	h.Disks = []hyperkit.Disk{disk}

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
	publicKey, err := os.ReadFile(i.Environmnet.KeyPath + "/id_rsa.pub")
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

func retryStart(attempts int, sleep time.Duration, f func(*hyperkit.HyperKit, string) error, h *hyperkit.HyperKit, cmdLine string) error {
	if err := f(h, cmdLine); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return s.error
		}

		if attempts--; attempts > 0 {
			// Add some randomness to prevent creating a Thundering Herd
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep = sleep + jitter/2

			time.Sleep(sleep)
			return retryStart(attempts, 2*sleep, f, h, cmdLine)
		}
		return err
	}

	return nil
}

func retryMacAddress(attempts int, sleep time.Duration, f func(string) (string, error), uuid string) (string, error) {
	var mac string
	var err error
	if mac, err = f(uuid); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return "", s.error
		}

		if attempts--; attempts > 0 {
			// Add some randomness to prevent creating a Thundering Herd
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep = sleep + jitter/2

			time.Sleep(sleep)
			return retryMacAddress(attempts, 2*sleep, f, uuid)
		}
		return "", err
	}

	return mac, nil
}

type stop struct {
	error
}
