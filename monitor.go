package main

import (
	"bufio"
	"io"
	"log"
	"os/exec"
)

func MonitorReader(rd io.Reader) <-chan string {
	scanner := bufio.NewScanner(rd)
	c := make(chan string)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				c <- line
			}
		}
	}()
	return c
}

func MonitorFiles(files ...string) <-chan string {
	args := append([]string{"-n", "0", "-F"}, files...)
	cmd := exec.Command("tail", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("could not create pipe:", err)
	}
	if err := cmd.Start(); err != nil {
		args = append([]string{"-n", "0", "-f"}, files...)
		cmd = exec.Command("tail", args...)
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			log.Fatal("could not create pipe:", err)
		}
		if err = cmd.Start(); err != nil {
			log.Fatal("could not invoke fallback tail:", err)
		}
	}
	return MonitorReader(stdout)
}
