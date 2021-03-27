package instance

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"

	"github.com/jedib0t/go-pretty/v6/table"
	yaml "gopkg.in/yaml.v2"
)

func (i *Instance) Get() error {
	existingInstances, err := i.List()
	instanceList := []*Instance{}
	if err != nil {
		return err
	}
	if i.Name == "" {
		instanceList = existingInstances
	} else {
		for _, inst := range existingInstances {
			if inst.Name == i.Name {
				instanceList = append(instanceList, inst)
			}
		}
	}
	i.Print(instanceList)
	return nil
}

func (i *Instance) Print(instanceList []*Instance) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"NAME", "DISTRIBUTION", "IP"})
	tableRows := []table.Row{}
	for _, inst := range instanceList {
		tableRows = append(tableRows, table.Row{inst.Name, inst.Distribution.Name, inst.IPAddress})
	}
	t.AppendRows(tableRows)
	t.Render()
}

func (i *Instance) List() ([]*Instance, error) {
	instanceList := []*Instance{}
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	directory := fmt.Sprintf("%s/.vmkit/instances", usr.HomeDir)
	instances, err := ioutil.ReadDir(directory)
	for _, dir := range instances {
		if dir.IsDir() {
			instYaml, err := os.ReadFile(directory + "/" + dir.Name() + "/instance.yaml")
			if err != nil {
				continue
			}
			inst := &Instance{}
			if err := yaml.Unmarshal(instYaml, inst); err != nil {
				return nil, err
			}
			instanceList = append(instanceList, inst)
		}
	}
	if err != nil {
		return nil, err
	}

	return instanceList, nil
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
