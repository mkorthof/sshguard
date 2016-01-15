package fw

import (
	"os/exec"
)

type IpfwBlocker struct{}

func ipfwCmd(args ...string) error {
	cmdArgs := append([]string{"table", "22"}, args...)
	cmd := exec.Command("ipfw", cmdArgs...)
	return cmd.Run()
}

func NewIpfwBlocker() IpfwBlocker {
	return IpfwBlocker{}
}

func (IpfwBlocker) Block(addr string) error {
	return ipfwCmd("add", addr)
}

func (IpfwBlocker) Flush() error {
	return ipfwCmd("flush")
}

func (IpfwBlocker) Release(addr string) error {
	return ipfwCmd("delete", addr)
}

func (IpfwBlocker) Init() error {
	return nil
}
