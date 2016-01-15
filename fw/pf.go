package fw

import (
	"os/exec"
)

type PfBlocker struct{}

func pfCmd(args ...string) error {
	cmd := exec.Command("pfctl", args...)
	return cmd.Run()
}

func NewPfBlocker() PfBlocker {
	return PfBlocker{}
}

func (PfBlocker) Block(addr string) error {
	return pfCmd("-k", addr, "-t", "sshguard", "-T", "add", addr)
}

func (PfBlocker) Flush() error {
	return pfCmd("-t", "sshguard", "-T", "flush")
}

func (PfBlocker) Release(addr string) error {
	return pfCmd("-t", "sshguard", "-T", "del", addr)
}

func (PfBlocker) Init() error {
	return nil
}
