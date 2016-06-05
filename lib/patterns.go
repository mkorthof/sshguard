package sshguard

// user matches any non-zero string suitable for usernames
const user = `(?P<user>.*)`

// ip4 matches the text part of IPv4 addresses (including 500.500.500.500)
const ip4 = `(?P<ip4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`

// addr matches the text part of IPv4 and IPv6 addresses
const addr = ip4

var Patterns = []string{
	// OpenSSH
	"[Ii]nvalid user " + user + " from " + addr,
	"User " + user + " from " + addr + " not allowed because",                                     // DenyUsers/DenyGroups on Ubuntu/FreeBSD
	"Failed .* for " + user + " from " + addr + " port \\d+ ssh",                                  // Ubuntu
	"error: PAM: [Aa]uthentication (error|failure) for (illegal user )?" + user + " from " + addr, // Debian
	"Did not receive identification string from " + addr,
	"(error: )?((Connection (closed|reset) by)|(Received disconnect from)) " + addr + "[: ].*\\[preauth\\]",
	"Bad protocol version identification .* from " + addr,

	// Solaris SSH
	`Failed none for <invalid username> from ` + addr + ` port`,
}
