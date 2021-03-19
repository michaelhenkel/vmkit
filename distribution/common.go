package distribution

import (
	"context"
	"log"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

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

func DockerRun(cmd, entrypoint []string, directory string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	_, err = cli.ImagePull(ctx, "djui/guestfs:latest", types.ImagePullOptions{})
	if err != nil {
		return err
	}
	//io.Copy(os.Stdout, reader)
	containerConfig := &container.Config{
		Image: "djui/guestfs:latest",
		Cmd:   cmd,
		Tty:   false,
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
		return err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return err
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)
	return nil
}
