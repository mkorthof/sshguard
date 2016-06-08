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

func watch(monitor <-chan string, blocker fw.Blocker, verbose bool) {
	attackers := make(map[string]Attacker)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINFO)
	defer func() {
		log.Println("exiting on signal; flushing blocked addresses")
		blocker.Flush()
	}()
	for {
		select {
		case input := <-monitor:
			if info, ok := sshguard.FilterSSH.Parse(input); ok {
				addr := info.Addr()
				if info.Score > 0 {
					// TODO: Cleanup here
					attacker := attackers[addr]
					attacker.addr = addr
					report(&attacker, blocker)
					attackers[addr] = attacker
				} else {
					// TODO: Delete from attackers table
					if verbose {
						log.Println("success for", addr)
					}
				}
			}
		case sig := <-sc:
			if sig == syscall.SIGINFO {
				dumpAttackers(attackers)
			} else {
				return
			}
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sshguard -f <backend> [flags] [file ...]")
	flag.PrintDefaults()
}

func initBackend(name string) (b fw.Blocker) {
	switch name {
	case "ipfw":
		b = fw.NewIpfwBlocker()
	case "null":
		b = fw.NewNullBlocker()
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

func parseCmdline() (c <-chan string, b fw.Blocker, vb bool) {
	flag.IntVar(&threshold, "a", 30, "Block when score exceeds `thresh`")
	flag.DurationVar(&initialBlock, "p", time.Minute*2,
		"Block first-time offenders for `duration`")

	backend := flag.String("f", "", "Block offenders using `backend`")
	noDaemon := flag.Bool("n", false, "Log to stderr instead of syslog")
	verbose := flag.Bool("verbose", false, "Print verbose log output")
	version := flag.Bool("version", false, "Show version")
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
	return c, b, *verbose
}

func main() {
	input, blocker, verbose := parseCmdline()
	if flag.NArg() < 1 {
		log.Println("monitoring stdin")
	} else {
		log.Println("monitoring", flag.Args())
	}
	watch(input, blocker, verbose)
}
