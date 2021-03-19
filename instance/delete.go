package instance

import (
	"os"
	"strconv"
	"syscall"
)

func (i *Instance) Delete() error {
	if err := i.Get(); err != nil {
		return err
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
		return err
	}

	if err := os.RemoveAll(i.Directory); err != nil {
		return err
	}
	return nil
}
