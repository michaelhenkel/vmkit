package environment

import (
	"fmt"
	"os"
	"os/user"
)

type Environment struct {
	ImagePath string
	KeyPath   string
}

func (e *Environment) Exists() (bool, error) {
	if _, err := os.Stat(e.ImagePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := os.Stat(e.KeyPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func Create() (*Environment, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	env := &Environment{
		ImagePath: fmt.Sprintf("%s/.vmkit/images", usr.HomeDir),
		KeyPath:   fmt.Sprintf("%s/.vmkit/keys", usr.HomeDir),
	}
	envExists, err := env.Exists()
	if err != nil {
		return nil, err
	}
	if !envExists {
		if err := os.MkdirAll(env.ImagePath, 0755); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(env.KeyPath, 0755); err != nil {
			return nil, err
		}
	}
	return env, nil
}
