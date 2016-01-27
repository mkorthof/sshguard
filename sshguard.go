package main

import (
	"bitbucket.org/sshguard/sshguard/fw"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Attacker struct {
	addr    string
	blocked bool
	score   int
	attacks int
}

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

// blockDuration calculates how long to block an attacker for.
func blockDuration(attacker Attacker) time.Duration {
	duration := initialBlock
	for i := 0; i < attacker.attacks-1; i++ {
		duration *= 2
	}
	return duration
}

// block 'addr' and unblock after sleeping for the given duration. Send 'addr'
// to the given channel after 'addr' is unblocked.
func block(addr string, blocker fw.Blocker, d time.Duration, c chan string) {
	if err := blocker.Block(addr); err != nil {
		log.Println("failed to block", addr, ":", err)
	} else {
		log.Println("blocking", addr, "for", d)
		time.Sleep(d)
		blocker.Release(addr)
	}
	c <- addr
}

// report is called for every log message that matches an attack pattern.
func report(attacker *Attacker, blocker fw.Blocker, c chan string) {
	score := 10
	attacker.score += score

	if attacker.blocked {
		log.Println(attacker.addr, "should already have been blocked")
	} else if attacker.score >= threshold {
		attacker.attacks += 1
		attacker.blocked = true
		go block(attacker.addr, blocker, blockDuration(*attacker), c)
	}
}

func watch(mon <-chan string, blocker fw.Blocker) {
	attackers := make(map[string]Attacker)
	p := NewParser(Patterns)

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	unblock := make(chan string, 1)
	for {
		select {
		case input := <-mon:
			if result := p.Parse(input); result != nil {
				addr := Addr(result)
				attacker := attackers[addr]
				attacker.addr = addr
				report(&attacker, blocker, unblock)
				attackers[addr] = attacker
			}
		case addr := <-unblock:
			attacker := attackers[addr]
			attacker.blocked = false
			attacker.score = 0
			attackers[addr] = attacker
		case <-exit:
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
		c = MonitorReader(os.Stdin)
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
