package instance

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func (i *Instance) Delete() error {
	usr, err := user.Current()
	if err != nil {
		return err
	}
	directory := fmt.Sprintf("%s/.vmkit/instances/%s", usr.HomeDir, i.Name)
	i.Directory = directory
	i.PidFile = directory + "/hyperkit.pid"

	directorExists, err := pathExists(directory)
	if err != nil {
		return err
	}
	if !directorExists {
		return errors.New("Instance directory doesn't exists")
	}

	jsonExists, err := pathExists(i.Directory + "/hyperkit.json")
	if err != nil {
		return err
	}
	if !jsonExists {
		return errors.New("Instance json doesn't exists")
	}
	pidByte, err := os.ReadFile(i.Directory + "/hyperkit.pid")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(string(pidByte))
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if err.Error() != "os: process already finished" {
			return err
		}
	}
	if err := os.RemoveAll(i.Directory); err != nil {
		return err
	}
	return nil
}
