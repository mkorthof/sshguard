package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Attacker struct {
	addr         string
	attacks      int
	score        int
	firstOffense time.Time
	lastOffense  time.Time
	unblockTime  time.Time
}

// blockDuration calculates how long to block an attacker for.
func (attacker Attacker) blockDuration() time.Duration {
	duration := initialBlock
	for i := 0; i < attacker.attacks-1; i++ {
		duration *= 2
	}
	return duration
}

func (a Attacker) blocked() bool {
	return !a.unblockTime.IsZero()
}

func dumpAttackers(attackers map[string]Attacker) {
	const filename = "attacks.csv"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("could not dump attackers", err)
		return
	}
	for _, attacker := range attackers {
		fmt.Fprintln(file, attacker)
	}
	log.Println("wrote attacks to", filename)
}
