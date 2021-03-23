package distribution

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

func ChownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}

func FileDirectoryExists(directory string) (bool, error) {
	if _, err := os.Stat(directory); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func FileDirectoryCreate(directory string) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	return nil
}

func DockerRun(cmd, entrypoint []string, directory string) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}

	_, err = cli.ImagePull(ctx, "leibniz9999/libguestfs-tools:latest", types.ImagePullOptions{})
	if err != nil {
		return "", err
	}
	//io.Copy(os.Stdout, reader)
	containerConfig := &container.Config{
		Image:      "leibniz9999/libguestfs-tools:latest",
		Cmd:        cmd,
		Tty:        true,
		WorkingDir: "/disk",
	}
	if entrypoint != nil {
		containerConfig.Entrypoint = entrypoint
	}
	containerHostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: directory,
				Target: "/disk",
			},
		},
	}
	resp, err := cli.ContainerCreate(ctx, containerConfig, containerHostConfig, nil, nil, "")
	if err != nil {
		log.Println(err)
		return "", err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return "", err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}
	defer out.Close()

	var p []byte
	_, err = out.Read(p)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	content, err := ioutil.ReadAll(out)
	if err != nil {
		return "", err
	}
	stdout := strings.TrimSuffix(string(content), "\n")
	return strings.TrimSuffix(stdout, "\r"), nil
}
