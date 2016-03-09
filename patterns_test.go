package main

import (
	"testing"
)

func checkNoMatch(t *testing.T, p *Parser, s string) {
	if p.Parse(s) != nil {
		t.Error("message should not match any attack:", s)
	}
}

func checkMatch(t *testing.T, p *Parser, s string) {
	if p.Parse(s) == nil {
		t.Error("message should match an attack:", s)
	}
}

func checkMatches(t *testing.T, match []string, noMatch []string) {
	p := NewParser(Patterns)
	for _, pattern := range match {
		checkMatch(t, p, pattern)
	}
	for _, pattern := range noMatch {
		checkNoMatch(t, p, pattern)
	}
}

func TestCucipop(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"authentication failure XYZ 6.6.6.0",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestCyrus(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"badlogin: XYZ [6.6.6.0] XYZ SASL XYZ checkpass failed",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestDovecot(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"imap-login: Aborted login (auth failed, 6 attempts): XYZ rip=6.6.6.0, lip=127.0.0.1",
		"pop3-login: Aborted login (auth failed, 1 attempts in 7 secs): user=<XYZ>, method=PLAIN, rip=6.6.6.0, lip=1.2.3.4, session=<Y8jIxw/97AAFZZ1Q>",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestExim(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"XYZ auth_plaintext authenticator failed for XYZ [6.6.6.0]:14432 I=XYZ : 535 Incorrect authentication data (set_id=test)",
		"expanded_prompt_plain authenticator failed for (test.host) [6.6.6.0] U=CALLER: 535 Incorrect authentication data (set_id=userx)",
		"login authenticator failed for vps.o2c.net (User) [6.6.6.0]: 535 Incorrect authentication data (set_id=dog)",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestFreeBSDFtpd(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"FTP LOGIN FAILED FROM 6.6.6.0, XYZ",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestPostfix(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"warning: unknown[6.6.6.0]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestProFtpd(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"foo.com (foo.com [6.6.6.0]) XYZ no such user XYZ",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestPureFtpd(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"(XYZ@6.6.6.0) [WARNING] Authentication failed for user XYZ",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestSendmail(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"Relaying denied. IP name lookup failed [6.6.6.0]",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestSSH(t *testing.T) {
	match := []string{
		"Bad protocol version identification XYZ from 6.6.6.0",
		"Connection closed by 6.6.6.0 [preauth]",
		"Did not receive identification string from 6.6.6.0",
		"Failed XYZ for XYZ from 6.6.6.0 port 14423 ssh2",
		"Invalid user  from 6.6.6.0",
		"Invalid user admin from 6.6.6.0",
		"Invalid user inexu from 6.6.6.0",
		"Received disconnect from 6.6.6.0: 11: Bye Bye [preauth]",
		"Received disconnect from 6.6.6.0: 11: These aren't the droids we're looking for. [preauth]",
		"User mario from 6.6.6.0 not allowed because XYZ",
		"error: PAM: authentication failure for mario from 6.6.6.0",
		"error: Received disconnect from 6.6.6.0: 14: No supported authentication methods available [preauth]",
		"error: Received disconnect from 6.6.6.0: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]",
	}
	nomatch := []string{
		"Received disconnect from 6.6.6.0: 11: disconnected by user",
		"reverse mapping checking getaddrinfo for XYZ [6.6.6.0] XYZ POSSIBLE BREAK-IN ATTEMPT!",
	}
	checkMatches(t, match, nomatch)
}
func TestUWImap(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"Login failed user=XYZ auth=XYZ host=XYZ [6.6.6.0]",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}

func TestVsftpd(t *testing.T) {
	t.Skip("Not implemented")
	match := []string{
		"XYZ FAIL LOGIN: Client \"6.6.6.0\"",
	}
	nomatch := []string{}
	checkMatches(t, match, nomatch)
}
