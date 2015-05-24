/*
 * Copyright (c) 2007,2008,2009,2011 Mij <mij@sshguard.net>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
/* for hton*() functions */
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>

#include <simclist.h>

#include "parser/attack.h"
#include "sshguard_log.h"
#include "sshguard_blacklist.h"

#define BL_MAXBUF      1024
#define BL_NUMENT      5

#define stringify(x)    xstr(x)
#define xstr(x)         #x

static FILE *blacklist_file;
static list_t *blacklist;

/*          UTILITY FUNCTIONS           */

/* seeks an address (key) into a list element (el). Callback for SimCList */
static int seeker_addr(const void *el, const void *key) {
    const sshg_address_t *adr = (const sshg_address_t *)key;
    const attacker_t *atk = (const attacker_t *)el;

    assert(atk != NULL && adr != NULL);
    
    if (atk->attack.address.kind != adr->kind) return 0;
    return (strcmp(atk->attack.address.value, adr->value) == 0);
}

static size_t attacker_el_meter(const void *el) {
    if (el) {}
    return sizeof(attacker_t);
}

/*          INTERFACE FUNCTIONS             */

static void blacklist_close() {
    assert(blacklist_file != NULL && blacklist != NULL);
    fclose(blacklist_file);
    blacklist_file = NULL;
    list_destroy(blacklist);
    free(blacklist);
    blacklist = NULL;
}

list_t *blacklist_load(const char *filename) {
    char blacklist_line[BL_MAXBUF];
    unsigned int linecnt;

    assert(blacklist_file == NULL && blacklist == NULL);
    blacklist_file = fopen(filename, "a+");
    if (blacklist_file == NULL) {
        return NULL;
    }

    blacklist = (list_t *)malloc(sizeof(list_t));
    list_init(blacklist);
    list_attributes_copy(blacklist, attacker_el_meter, 1);
    rewind(blacklist_file);

    /* loading content of the file in the blacklist */
    for (linecnt = 1; fgets(blacklist_line, BL_MAXBUF, blacklist_file) != NULL; ++linecnt) {
        attacker_t newattacker;

        /* discard empty lines and lines starting with a white-space or # */
        if (isspace(blacklist_line[0]) || blacklist_line[0] == '#') {
            while (blacklist_line[strlen(blacklist_line)-1] != '\n') {
                /* consume until end of line */
                if (fgets(blacklist_line, BL_MAXBUF, blacklist_file) == NULL) return blacklist;
            }
            continue;
        }

        /* line is valid, do create a list entry for it */
        if (sscanf(blacklist_line, "%lu|%d|%d|%" stringify(ADDRLEN) "s", & newattacker.whenlast,
               & newattacker.attack.service,
               & newattacker.attack.address.kind, newattacker.attack.address.value) != 4) {
            sshguard_log(LOG_NOTICE, "Blacklist entry (line #%d of '%s') appears to be malformatted. Ignoring.", linecnt, filename);
            continue;
        }
        if (newattacker.attack.address.kind != ADDRKIND_IPv4 && newattacker.attack.address.kind != ADDRKIND_IPv6) {
            /* unknown address type */
            sshguard_log(LOG_NOTICE, "Blacklist entry (line #%d of '%s') has unknown type %d. Ignoring.", linecnt, filename, newattacker.attack.address.kind);
            continue;
        }

        /* initialization of other default information */
        newattacker.attack.dangerousness = 1;
        newattacker.whenfirst = 0;
        newattacker.pardontime = 0;
        newattacker.numhits = 1;
        newattacker.cumulated_danger = 1;

        /* add new element to the blacklist */
        list_append(blacklist, & newattacker);
    }

    atexit(blacklist_close);
    return blacklist;
}

void blacklist_add(const attacker_t *restrict newel) {
    assert(blacklist_file != NULL && blacklist != NULL);
    int retval = fprintf(blacklist_file, "%lu|%d|%d|%s\n",
            newel->whenlast, newel->attack.service,
            newel->attack.address.kind, newel->attack.address.value);

    if (retval > 0) {
        sshguard_log(LOG_DEBUG, "Attacker '%s:%d' blacklisted.",
                newel->attack.address.value, newel->attack.address.kind);
        fflush(blacklist_file);
        list_append(blacklist, newel);
    } else {
        sshguard_log(LOG_ERR, "Could not update blacklist: %s", strerror(errno));
    }
}

int blacklist_contains(const sshg_address_t *restrict addr) {
    if (blacklist == NULL) {
        // Blacklist hasn't been loaded yet.
        return -1;
    }

    sshguard_log(LOG_DEBUG, "Looking for address '%s:%d'...", addr->value, addr->kind);
    list_attributes_seeker(blacklist, seeker_addr);
    attacker_t *restrict el = list_seek(blacklist, addr);

    if (el != NULL)
        sshguard_log(LOG_DEBUG, "Found!");
    else
        sshguard_log(LOG_DEBUG, "Not found.");

    return (el != NULL);
}

