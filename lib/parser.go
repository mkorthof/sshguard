package sshguard

import (
	"regexp"
)

// user matches any string
const user = `(?P<user>.*)`

// ip4 textually matches IPv4 addresses without any validity checks
const ip4 = `(?P<ip4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`

// addr textually matches either IPv4 or IPv6 addresses
const addr = ip4

// extract returns a map from the names of parenthesized sub-expressions to
// their values.
func extract(re *regexp.Regexp, s string) map[string]string {
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return nil
	}

	names := re.SubexpNames()
	results := make(map[string]string)
	for i, name := range names {
		if i != 0 && name != "" {
			results[name] = matches[i]
		}
	}
	return results
}

// rules is a convenience type for writing rules for services.
type rules struct {
	name    string
	attacks []string // (e.g. login failures)
	spam    []string // (e.g. preauth disconnection)
	success []string // (e.g. login success)
}

// service transforms rules into a service ruleset for the parser.
func (r rules) service() (sv service) {
	sv = service{r.name, []int{}, []*regexp.Regexp{}}
	addAll := func(patterns []string, score int) {
		for _, p := range patterns {
			sv.score = append(sv.score, score)
			sv.re = append(sv.re, regexp.MustCompile(p))
		}
	}
	addAll(r.attacks, 3)
	addAll(r.spam, 1)
	addAll(r.success, 0)
	return sv
}

// service is a ruleset for a particular service used by the parser.
type service struct {
	name  string
	score []int
	re    []*regexp.Regexp
}

// Parse returns details of an attack or false if there's no match.
func (sv service) Parse(s string) (AttackInfo, bool) {
	for i, re := range sv.re {
		if result := extract(re, s); result != nil {
			return AttackInfo{sv.score[i],
				result["ip4"], result["ip6"], result["user"]}, true
		}
	}
	return AttackInfo{}, false
}

type AttackInfo struct {
	score    int
	ip4, ip6 string
	user     string
}

// Addr returns a string with either the IPv6 or IPv4 address of an attack.
func (info AttackInfo) Addr() string {
	if info.ip6 != "" {
		return info.ip6
	}
	return info.ip4
}

var FilterSSH = rules{"sshd",
	[]string{
		// OpenSSH
		"[Ii]nvalid user " + user + " from " + addr,
		"User " + user + " from " + addr + " not allowed because",                                     // DenyUsers/DenyGroups on Ubuntu/FreeBSD
		"Failed .* for " + user + " from " + addr + " port \\d+ ssh",                                  // Ubuntu
		"error: PAM: [Aa]uthentication (error|failure) for (illegal user )?" + user + " from " + addr, // Debian

		// Solaris SSH
		`Failed none for <invalid username> from ` + addr + ` port`,
	}, []string{
		"Did not receive identification string from " + addr,
		"(error: )?((Connection (closed|reset) by)|(Received disconnect from)) " + addr + "[: ].*\\[preauth\\]",
		"Bad protocol version identification .* from " + addr,
	}, nil}.service()
