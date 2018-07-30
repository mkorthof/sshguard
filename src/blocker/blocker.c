/*
 * Copyright (c) 2007,2008,2009,2010 Mij <mij@sshguard.net>
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

#include "config.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>
#include "queries.h"

#include "blocklist.h"
#include "sandbox.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"
#include "sshguard_options.h"
#include "sshguard_whitelist.h"

/** Keep track of the exit signal received. */
static volatile sig_atomic_t exit_sig = 0;

/* handler for termination-related signals */
static void sigfin_handler();
/* called at exit(): flush blocked addresses and finalize subsystems */
static void finishup(void);

/* handle an attack: addr is the author, addrkind its address kind, service the attacked service code */
static void report_address(attack_t attack);

sqlite3 *db;

static void my_pidfile_create() {
    FILE *p = fopen(opts.my_pidfile, "w");
    if (p == NULL) {
        sshguard_log(LOG_ERR, "Failed to create pid file: %m");
        exit(73);
    }

    fprintf(p, "%d\n", (int)getpid());
    fclose(p);
}

static void my_pidfile_destroy() {
    if (unlink(opts.my_pidfile) != 0) {
        sshguard_log(LOG_ERR, "Failed to remove pid file: %m");
    }
}

static void init_log(int debug) {
    int flags = LOG_NDELAY | LOG_PID;
    int dest = LOG_AUTH;

    if (debug) {
        flags |= LOG_PERROR;
        dest = LOG_LOCAL6;
    } else {
        setlogmask(LOG_UPTO(LOG_NOTICE));
    }

    // Set local time zone and open log before entering sandbox.
    tzset();
    openlog("sshguard", flags, dest);
}

static void sqlite_perror(const char msg[static 1]) {
    fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
}

int main(int argc, char *argv[]) {
    int sshg_debugging = (getenv("SSHGUARD_DEBUG") != NULL);
    init_log(sshg_debugging);
    srand(time(NULL));

    if (!sqlite3_threadsafe())
        abort();

    // Initialize whitelist before parsing arguments.
    whitelist_init();

    if (get_options_cmdline(argc, argv) != 0) {
        exit(64);
    }

    if (opts.my_pidfile != NULL) {
        my_pidfile_create();
        atexit(my_pidfile_destroy);
    }

    const char* dbname;
    if (opts.blacklist_filename != NULL) {
        dbname = opts.blacklist_filename;
    } else {
        dbname = ":memory:";
    }
    if (sqlite3_open(dbname, &db) != SQLITE_OK) {
        sqlite_perror("failed to open database");
        exit(1);
    }

    if (sqlite3_exec(db, sql_init, NULL, NULL, NULL)) {
        sqlite_perror("failed to initialize database");
        fprintf(stderr, "If %s is in an old format, please convert it.\n",
                dbname);
        exit(1);
    }
    db_prepare_all();

    /* termination signals */
    signal(SIGTERM, sigfin_handler);
    signal(SIGHUP, sigfin_handler);
    signal(SIGINT, sigfin_handler);
    atexit(finishup);

    /* whitelist localhost */
    if (whitelist_add("127.0.0.1") != 0) {
        fprintf(stderr, "Could not whitelist localhost. Terminating...\n");
        exit(1);
    }
    whitelist_conf_fin();

    // Initialize firewall
    printf("flushonexit\n");
    fflush(stdout);

    unblock_expired(false);
    int ret;
    sqlite3_reset(stmt_get_initial_blocks);
    do {
        ret = sqlite3_step(stmt_get_initial_blocks);
        if (ret == SQLITE_DONE) break;
        const unsigned char* address = sqlite3_column_text(stmt_get_initial_blocks, 0);
        int type = sqlite3_column_int(stmt_get_initial_blocks, 1);
        fw_block(address, type);
    } while (ret == SQLITE_ROW);
    
    blocklist_init();

    sshguard_log(LOG_INFO, "Now monitoring attacks.");

    char buf[1024];
    attack_t parsed_attack;
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        if (sscanf(buf, "%d %46s %d %d\n", (int*)&parsed_attack.service,
                  parsed_attack.address.value, &parsed_attack.address.kind,
                  &parsed_attack.dangerousness) == 4) {
            report_address(parsed_attack);
        } else {
            sshguard_log(LOG_ERR, "Could not parse attack data.");
            exit(65);
        }
    }

    if (feof(stdin)) {
        sshguard_log(LOG_DEBUG, "Received EOF from stdin.");
    }
}

/*
 * This function is called every time an attack pattern is matched.
 * It does the following:
 * 1) update the attacker info
 * 2) block the attacker, if attacks > threshold (abuse)
 * 3) blacklist the address, if the number of abuses is excessive
 */
static void report_address(attack_t attack) {
    assert(attack.address.value != NULL);
    assert(memchr(attack.address.value, '\0', sizeof(attack.address.value)) != NULL);

    int ret;
    sqlite3_reset(stmt_add_attacker);
    sqlite3_bind_text(stmt_add_attacker, 1, attack.address.value, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt_add_attacker, 2, attack.address.kind);
    ret = sqlite3_step(stmt_add_attacker);
    if (ret != SQLITE_DONE) {
        sqlite_perror("could not insert attacker");
        return;
    }

    sqlite3_reset(stmt_get_id);
    sqlite3_bind_text(stmt_get_id, 1, attack.address.value, -1, SQLITE_STATIC);
    ret = sqlite3_step(stmt_get_id);
    if (ret != SQLITE_ROW) {
        sqlite_perror("could not get attacker id");
        return;
    }
    int id = sqlite3_column_int(stmt_get_id, 0);
    int blocked = sqlite3_column_int(stmt_get_id, 1);

    /* address already blocked? (can happen for 100 reasons) */
    if (blocked) {
        sshguard_log(LOG_INFO, "%s has already been blocked.",
                     attack.address.value);
        return;
    }

    if (whitelist_match(attack.address.value, attack.address.kind)) {
        sshguard_log(LOG_INFO, "%s: not blocking (on whitelist)",
                     attack.address.value);
        return;
    }

    sshguard_log(LOG_NOTICE,
                 "Attack from \"%s\" on service %d with danger %u.",
                 attack.address.value, attack.service,
                 attack.dangerousness);

    sqlite3_reset(stmt_add_attack);
    sqlite3_bind_int(stmt_add_attack, 1, id);
    sqlite3_bind_int(stmt_add_attack, 2, attack.service);
    sqlite3_bind_int(stmt_add_attack, 3, attack.dangerousness);
    ret = sqlite3_step(stmt_add_attack);
    if (ret != SQLITE_DONE) {
        sqlite_perror("could not add attack");
        return;
    }

    sqlite3_reset(stmt_get_score_since_last_block);
    sqlite3_bind_int(stmt_get_score_since_last_block, 1, id);
    ret = sqlite3_step(stmt_get_score_since_last_block);
    if (ret != SQLITE_ROW) {
        sqlite_perror("could not get last attacks");
        return;
    }
    int cum_since = sqlite3_column_int(stmt_get_score_since_last_block, 0);

    if (cum_since < opts.abuse_threshold) {
        /* do nothing now, just keep an eye on this guy */
        return;
    }

    /* Let's see if we _also_ need to blacklist it. */
    sqlite3_reset(stmt_get_cum_score);
    sqlite3_bind_int(stmt_get_cum_score, 1, id);
    ret = sqlite3_step(stmt_get_cum_score);
    if (ret != SQLITE_ROW) {
        sqlite_perror("could not get cum score");
        return;
    }
    int cum = sqlite3_column_int(stmt_get_cum_score, 0);

    time_t pardontime = opts.pardon_threshold;
    if (opts.blacklist_filename != NULL && cum >= opts.blacklist_threshold) {
        pardontime = 2592000; // 30 days
    } else {
        /* compute blocking time wrt the "offensiveness" */
        for (unsigned int i = 0; i < cum / opts.abuse_threshold; i++) {
            pardontime *= 2;
        }
    }
    sshguard_log(LOG_WARNING, "blocking %s for %lu seconds",
                 attack.address.value, pardontime);

    sqlite3_reset(stmt_add_block);
    sqlite3_bind_int(stmt_add_block, 1, id);
    sqlite3_bind_int64(stmt_add_block, 2, time(NULL) + pardontime);
    ret = sqlite3_step(stmt_add_block);
    if (ret != SQLITE_DONE) {
        sqlite_perror("could not add block");
        return;
    }

    fw_block(attack.address.value, attack.address.kind);
}

static void finishup(void) {
    sshguard_log(LOG_INFO, "Exiting on %s.",
            exit_sig == SIGHUP ? "SIGHUP" : "signal");
    whitelist_fin();
    closelog();
    db_finalize_all();
    sqlite3_close(db);
}

static void sigfin_handler(int sig) {
    exit_sig = sig;
    exit(0);
}
