package main

import (
	"fmt"
	"testing"
)

func TestPatterns(t *testing.T) {
	p := NewParser(Patterns)
	attacks := []string{
		"(XYZ@6.6.6.0) [WARNING] Authentication failed for user XYZ",
		"Bad protocol version identification XYZ from 6.6.6.0",
		"Connection closed by 6.6.6.0 [preauth]",
		"Did not receive identification string from 6.6.6.0",
		"FTP LOGIN FAILED FROM 6.6.6.0, XYZ",
		"Failed XYZ for XYZ from 6.6.6.0 port 14423 ssh2",
		"Invalid user admin from 6.6.6.0",
		"Invalid user inexu from 6.6.6.0",
		"Login failed user=XYZ auth=XYZ host=XYZ [6.6.6.0]",
		"Received disconnect from 6.6.6.0: 11: Bye Bye [preauth]",
		"Received disconnect from 6.6.6.0: 11: These aren't the droids we're looking for. [preauth]",
		"Relaying denied. IP name lookup failed [6.6.6.0]",
		"User mario from 6.6.6.0 not allowed because XYZ",
		"XYZ FAIL LOGIN: Client \"6.6.6.0\"",
		"XYZ auth_plaintext authenticator failed for XYZ [6.6.6.0]:14432 I=XYZ : 535 Incorrect authentication data (set_id=test)",
		"authentication failure XYZ 6.6.6.0",
		"badlogin: XYZ [6.6.6.0] XYZ SASL XYZ checkpass failed",
		"error: PAM: authentication failure for mario from 6.6.6.0",
		"error: Received disconnect from 6.6.6.0: 14: No supported authentication methods available [preauth]",
		"error: Received disconnect from 6.6.6.0: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]",
		"expanded_prompt_plain authenticator failed for (test.host) [6.6.6.0] U=CALLER: 535 Incorrect authentication data (set_id=userx)",
		"foo.com (foo.com [6.6.6.0]) XYZ no such user XYZ",
		"imap-login: Aborted login (auth failed, 6 attempts): XYZ rip=6.6.6.0, lip=127.0.0.1",
		"login authenticator failed for vps.o2c.net (User) [6.6.6.0]: 535 Incorrect authentication data (set_id=dog)",
		"reverse mapping checking getaddrinfo for XYZ [6.6.6.0] XYZ POSSIBLE BREAK-IN ATTEMPT!",
		"warning: unknown[6.6.6.0]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
	}

	for _, pattern := range attacks {
		fmt.Println(p.Parse(pattern))
	}
}
