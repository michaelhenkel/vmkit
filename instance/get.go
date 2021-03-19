package instance

import (
	"errors"
	"fmt"
	"os"
	"os/user"
)

func (i *Instance) Get() error {
	usr, err := user.Current()
	if err != nil {
		return err
	}
	directory := fmt.Sprintf("%s/.vmkit/%s", usr.HomeDir, i.Name)
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

	return nil
}

func pathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
