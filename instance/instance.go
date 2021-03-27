package instance

import (
	"bufio"
	"errors"
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
	"sync"
	"syscall"
	"time"

	"github.com/docker/machine/libmachine/state"
	spinner "github.com/janeczku/go-spinner"
	"github.com/kdomanski/iso9660"
	"github.com/michaelhenkel/vmkit/distribution"
	"github.com/michaelhenkel/vmkit/environment"
	"github.com/michaelhenkel/vmkit/vmnet"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	ps "github.com/mitchellh/go-ps"
	hyperkit "github.com/moby/hyperkit/go"
	log "github.com/sirupsen/logrus"
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
	Name         string                     `yaml:"name"`
	Directory    string                     `yaml:"directory"`
	PidFile      string                     `yaml:"pidFile"`
	Distribution *distribution.Distribution `yaml:"distribution"`
	Environmnet  *environment.Environment
	IPAddress    string `yaml:"ipAddress"`
	CmdLine      string
	UUID         string
	CPU          int         `yaml:"cpu"`
	Memory       int         `yaml:"memory"`
	ResultCh     chan Result `yaml:"-"`
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
	//log.Infof("creating instance %s", i.Name)
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

func (i *Instance) updateKnownHosts(line string) error {
	/*
		publicKeyByte, err := os.ReadFile(i.Environmnet.KeyPath + "/id_rsa.pub")
		if err != nil {
			return err
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyByte)

		if err != nil {
			return err
		}
		if err := addHostKey(i.Name, i.IPAddress, publicKey); err != nil {
			return err
		}
	*/
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return err
	}
	if err := addHostKey(i.Name, i.IPAddress, publicKey); err != nil {
		return err
	}
	/*
		khFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
		f, err := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
	*/
	return nil
}

func addHostKey(host string, remote string, pubKey ssh.PublicKey) error {
	// add host key if host is not found in known_hosts, error object is return, if nil then connection proceeds,
	// if not nil then connection stops.
	khFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	f, err := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	knownHosts := knownhosts.Normalize(remote)
	_, err = f.WriteString(knownhosts.Line([]string{knownHosts}, pubKey) + "\n")
	return err
}

func (i *Instance) create() error {
	startString := fmt.Sprintf(" %s : getting images", i.Name)
	s := spinner.StartNew(startString)
	s.Start()
	initrd := "initrd"
	kernel := "vmlinuz"
	rootfs := "disk.raw"

	distroPath := i.Environmnet.ImagePath + "/" + string(i.Distribution.Type) + "/" + i.Distribution.Name
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
	s.Stop()

	if err := verifyRootPermissions(); err != nil {
		return err
	}

	startString = fmt.Sprintf(" %s : starting instance", i.Name)
	s2 := spinner.NewSpinner(startString)
	s2.Start()
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
	s2.Stop()
	/*
		_, err = h.Start(i.CmdLine)
		if err != nil {
			return err
		}
	*/

	startString = fmt.Sprintf(" %s : waiting for network", i.Name)
	s3 := spinner.NewSpinner(startString)
	s3.Start()
	if err := i.setupIP(mac); err != nil {
		return err
	}
	s3.Stop()
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
	instYaml, err := yaml.Marshal(i)
	if err != nil {
		return err
	}
	if err := os.WriteFile(i.Directory+"/instance.yaml", instYaml, 0660); err != nil {
		return err
	}
	if err := chownR(i.Directory+"/instance.yaml", os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	startString = fmt.Sprintf(" %s : waiting for ssh", i.Name)
	s4 := spinner.NewSpinner(startString)
	s4.Start()
	if err := sshKeyScan(i.Distribution.Image.DefaultUser, i.IPAddress); err != nil {
		return err
	}
	s4.Stop()
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

	h.Kernel = i.Directory + "/vmlinuz"
	h.Initrd = i.Directory + "/initrd"
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
		Path: i.Directory + "/disk.raw",
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

func retrySshDial(attempts int, sleep time.Duration, f func(string, string, *ssh.ClientConfig) (*ssh.Client, error), network string, addr string, config *ssh.ClientConfig) error {
	if _, err := f(network, addr, config); err != nil {
		if err.Error() != "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain" {
			if s, ok := err.(stop); ok {
				// Return the original error for later checking
				return s.error
			}

			if attempts--; attempts > 0 {
				// Add some randomness to prevent creating a Thundering Herd
				//log.Infof("waiting for ssh connection, retry attempt %d\n", attempts)
				//log.Infof("err %s\n", err)
				//jitter := time.Duration(rand.Int63n(int64(sleep)))
				//sleep = sleep + jitter/2
				//log.Infof("sleeping for %f\n", sleep.Seconds())
				time.Sleep(sleep)
				return retrySshDial(attempts, sleep, f, network, addr, config)
			}
			return err
		}
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

var Ch chan map[string]string = make(chan map[string]string)

func KeyScanCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	//Ch <- fmt.Sprintf("%s %s", hostname[:len(hostname)-3], string(ssh.MarshalAuthorizedKey(key)))
	Ch <- map[string]string{hostname[:len(hostname)-3]: string(ssh.MarshalAuthorizedKey(key))}
	//Ch <- fmt.Sprintf("%s", string(ssh.MarshalAuthorizedKey(key)))
	return nil
}

func dial(server string, config *ssh.ClientConfig, wg *sync.WaitGroup) {
	if err := retrySshDial(60, time.Duration(time.Second*2), ssh.Dial, "tcp", fmt.Sprintf("%s:%d", server, 22), config); err != nil {
		log.Fatalln("Failed to dial:", err)
	}
	/*
		_, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", server, 22), config)
		if err != nil {
			log.Fatalln("Failed to dial:", err)
		}
	*/
	wg.Done()
}

var knownHostEntry string

func out(wg *sync.WaitGroup) {
	for s := range Ch {
		for k, v := range s {
			//knownHostEntry = fmt.Sprintf("%s", v)
			publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
			if err != nil {
				log.Error(err)
				wg.Done()
			}
			khFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
			f, err := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				log.Error(err)
				wg.Done()
			}
			defer f.Close()

			knownHosts := knownhosts.Normalize(k)
			_, err = f.WriteString(knownhosts.Line([]string{knownHosts}, publicKey) + "\n")
			wg.Done()
		}

	}
}

func sshKeyScan(username, host string) error {
	auth_socket := os.Getenv("SSH_AUTH_SOCK")
	if auth_socket == "" {
		return errors.New("no $SSH_AUTH_SOCK defined")
	}
	conn, err := net.DialTimeout("unix", auth_socket, time.Duration(time.Minute*1))
	if err != nil {
		return err
	}
	defer conn.Close()
	ag := agent.NewClient(conn)
	auths := []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auths,
		HostKeyCallback: KeyScanCallback,
		Timeout:         time.Minute * 1,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go out(&wg)
	go dial(host, config, &wg)
	wg.Wait()
	return nil
}
