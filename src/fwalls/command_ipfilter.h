/*
 * Copyright (c) 2007,2008,2010 Mij <mij@sshguard.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SSHGuard. See http://www.sshguard.net
 */
#ifndef COMMAND_H
#define COMMAND_H

/* user-define backend ipfilter */
#include "../config.h"

#define COMMAND_INIT       "grep -qE '^##sshguard-begin##\n##sshguard-end##$' < " IPFILTER_CONFFILE
#define COMMAND_FIN        ""
#define COMMAND_BLOCK      "if test $SSHG_ADDRKIND != 4; then exit 1 ; fi ; TMP=`mktemp /tmp/ipfconf.XXXXX` && awk '1 ; /^##sshguard-begin##$/ { print \"block in quick proto tcp from '\"$SSHG_ADDR\"' to any\" }' <" IPFILTER_CONFFILE " > $TMP && mv $TMP " IPFILTER_CONFFILE " && " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#define COMMAND_RELEASE    "if test $SSHG_ADDRKIND != 4; then exit 1 ; fi ; TMP=`mktemp /tmp/ipfconf.XXXXX` && awk 'BEGIN { copy = 1 } copy ; /^##sshguard-begin##$/    { copy = 0 ; next } !copy { if ($0 !~ /'\"$SSHG_ADDR\"'.*/) print $0 } /^##sshguard-end##$/  { copy = 1 }' <" IPFILTER_CONFFILE " >$TMP && mv $TMP " IPFILTER_CONFFILE " && " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#define COMMAND_FLUSH      "TMP=`mktemp /tmp/ipfconf.XXXXX` && awk 'BEGIN { copy = 1 } /^##sshguard-begin##$/ { print $0 ; copy = 0 } /^##sshguard-end##$/ { copy = 1 } copy' <" IPFILTER_CONFFILE " >$TMP ; mv $TMP " IPFILTER_CONFFILE " ; " IPFPATH "/ipf -Fa && " IPFPATH "/ipf -f " IPFILTER_CONFFILE
#endif
