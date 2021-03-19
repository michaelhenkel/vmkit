package environment

import (
	"fmt"
	"os"
	"os/user"
)

type Environment struct {
	BasePath string
}

func (e *Environment) Exists() (bool, error) {
	if _, err := os.Stat(e.BasePath); err != nil {
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
		BasePath: fmt.Sprintf("%s/.vmkit/images", usr.HomeDir),
	}
	envExists, err := env.Exists()
	if err != nil {
		return nil, err
	}
	if !envExists {
		if err := os.MkdirAll(env.BasePath, 0755); err != nil {
			return nil, err
		}
	}
	return env, nil
}
