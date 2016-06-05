package main

import (
	"bitbucket.org/sshguard/sshguard/fw"
	sshguard "bitbucket.org/sshguard/sshguard/lib"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var initialBlock time.Duration
var threshold int

// initSyslog sets up the standard logger to log to syslog(3).
func initSyslog() {
	logger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_AUTH, "sshguard")
	if err != nil {
		log.Println("could not open syslog:", err)
		return
	}

	log.SetFlags(0)
	log.SetOutput(logger)
}

// report is called for every log message that matches an attack pattern.
func report(attacker *Attacker, blocker fw.Blocker) {
	const score = 10
	attacker.score += score

	if attacker.blocked() {
		log.Println(attacker.addr, "should already have been blocked")
	} else if attacker.score >= threshold {
		attacker.attacks += 1
		duration := attacker.blockDuration()
		attacker.unblockTime = time.Now().Add(duration)
		if err := blocker.Block(attacker.addr); err != nil {
			log.Println("failed to block", attacker.addr, ":", err)
		} else {
			log.Println("blocking", attacker.addr, "for", duration)
		}
	}
}

/*
func unblock() {
	attacker := attackers[addr]
	attacker.blocked = false
	attacker.score = 0
	attackers[addr] = attacker
}
*/

func watch(mon <-chan string, blocker fw.Blocker) {
	attackers := make(map[string]Attacker)
	p := sshguard.NewParser(sshguard.Patterns)

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINFO)
	for {
		select {
		case input := <-mon:
			if result := p.Parse(input); result != nil {
				addr := result.Addr()
				attacker, ok := attackers[addr]
				if !ok {
					attacker.addr = addr
				}
				report(&attacker, blocker)
				attackers[addr] = attacker
			}
		case sig := <-exit:
			if sig == syscall.SIGINFO {
				dumpAttackers(attackers)
				break
			}
			log.Println("exiting on signal; flushing blocked addresses")
			blocker.Flush()
			return
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sshguard [flags] [file ...]")
	flag.PrintDefaults()
}

// initBackend initializes a backend or exits on failure.
func initBackend(name string) (b fw.Blocker) {
	switch name {
	case "ipfw":
		b = fw.NewIpfwBlocker()
	case "pf":
		b = fw.NewPfBlocker()
	default:
		usage()
		os.Exit(64)
	}

	if err := b.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "could not flush addresses: check permissions")
		os.Exit(77)
	}
	return b
}

func parseCmdline() (c <-chan string, b fw.Blocker) {
	flag.IntVar(&threshold, "a", 30,
		"Block an address when its dangerousness exceeds `score`.")
	noDaemon := flag.Bool("d", false,
		"Do not daemonize. Run in the foreground and log to stderr.")
	backend := flag.String("f", "none", "Firewall or `backend` to use.")
	flag.DurationVar(&initialBlock, "p", time.Minute*2,
		"Block attackers for the given initial `duration`.")
	version := flag.Bool("v", false, "Print version information and exit.")
	flag.Usage = usage
	flag.Parse()

	if *version {
		fmt.Println("sshguard 2.0.0")
		os.Exit(0)
	}

	b = initBackend(*backend)
	if flag.NArg() < 1 {
		c = Monitor(os.Stdin)
	} else {
		c = MonitorFiles(flag.Args()...)
	}

	if !*noDaemon {
		initSyslog()
	}
	return c, b
}

func main() {
	input, blocker := parseCmdline()
	if flag.NArg() < 1 {
		log.Println("monitoring stdin")
	} else {
		log.Println("monitoring", flag.Args())
	}
	watch(input, blocker)
}
