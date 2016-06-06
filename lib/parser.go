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

func extract(re *regexp.Regexp, s string) AttackInfo {
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return nil
	}

	names := re.SubexpNames()
	results := make(AttackInfo)
	for i, name := range names {
		if i != 0 && name != "" {
			results[name] = matches[i]
		}
	}
	return results
}

// service is a convenience type used for writing service filters.
type service struct {
	name    string
	attacks []string // (e.g. login failures)
	spam    []string // (e.g. preauth disconnection)
	success []string // (e.g. login success)
}

// MakeFilter creates a serviceFilter from a service and exits on error.
func (s service) MakeFilter() (sf serviceFilter) {
	sf = serviceFilter{}
	sf.name = s.name
	sf.score = []int{}
	sf.re = []*regexp.Regexp{}
	addAll := func(patterns []string, score int) {
		for _, p := range patterns {
			sf.score = append(sf.score, score)
			sf.re = append(sf.re, regexp.MustCompile(p))
		}
	}
	addAll(s.attacks, 3)
	addAll(s.spam, 1)
	addAll(s.success, 0)
	return sf
}

// Group of attacks on a particular service
type serviceFilter struct {
	name  string
	score []int
	re    []*regexp.Regexp
}

// Parse extracts details of an attack or returns nil if no match.
func (sf serviceFilter) Parse(s string) AttackInfo {
	for _, re := range sf.re {
		if result := extract(re, s); result != nil {
			result["service"] = sf.name
			return result
		}
	}
	return nil
}

type AttackInfo map[string]string

// Addr returns the value of the address fields of a string-string map.
func (values AttackInfo) Addr() string {
	if ip6, ok := values["ip6"]; ok {
		return ip6
	}
	return values["ip4"]
}

var FilterSSH = service{"sshd",
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
	}, nil}.MakeFilter()
