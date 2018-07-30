#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sqlite3.h>
#include "queries.h"

#include "blocklist.h"
#include "simclist.h"
#include "sshguard_blacklist.h"
#include "sshguard_log.h"
#include "sshguard_options.h"

/* list of addresses currently blocked (offenders) */
static list_t hell;

/* mutex against races between insertions and pruning of lists */
static pthread_mutex_t list_mutex;

unsigned int fw_block_subnet_size(int inet_family) {
    if (inet_family == 6) {
      return opts.subnet_ipv6;
    } else if (inet_family == 4) {
      return opts.subnet_ipv4;
    }

    assert(0);
}

void fw_block(const char address[static 1], int kind) {
    unsigned int subnet_size = fw_block_subnet_size(kind);
    printf("block %s %d %u\n", address, kind, subnet_size);
    fflush(stdout);
}

void fw_release(const char address[static 1], int kind) {
    unsigned int subnet_size = fw_block_subnet_size(kind);
    printf("release %s %d %u\n", address, kind, subnet_size);
    fflush(stdout);
}

/**
 * Remove expired attackers from the block list, and if release is true,
 * unblock them from the firewall. Setting release to false is useful for
 * unblocking persisted attacks when SSHGuard is just starting up.
 */
void unblock_expired(bool release) {
    int ret;
    sqlite3_reset(stmt_get_score_since_last_block);
    do {
        ret = sqlite3_step(stmt_get_releases);
        if (ret == SQLITE_DONE) break;
        int id = sqlite3_column_int(stmt_get_releases, 0);
        const unsigned char* address = sqlite3_column_text(stmt_get_releases, 1);
        int type = sqlite3_column_int(stmt_get_releases, 2);
        if (release) {
            sshguard_log(LOG_DEBUG, "unblocking %s", address);
            fw_release(address, type);
        }
        sqlite3_reset(stmt_release);
        sqlite3_bind_int(stmt_release, 1, id);
        sqlite3_step(stmt_release);
    } while (ret == SQLITE_ROW);
}

static void *unblock_loop() {
    while (1) {
        /* wait some time, at most opts.pardon_threshold/3 + 1 sec */
        sleep(1 + ((unsigned int)rand() % (1 + opts.pardon_threshold / 2)));
        unblock_expired(true);
    }

    pthread_exit(NULL);
    return NULL;
}

void blocklist_init() {
    pthread_t tid;

    /* start thread for purging stale blocked addresses */
    if (pthread_create(&tid, NULL, unblock_loop, NULL) != 0) {
        perror("pthread_create()");
        exit(2);
    }
}

static void block_list(list_t *list) {
    list_iterator_start(list);
    while (list_iterator_hasnext(list)) {
        attacker_t *next = list_iterator_next(list);
        fw_block(next->attack.address.value, next->attack.address.kind);
    }
    list_iterator_stop(list);
}

void blacklist_load_and_block() {
    list_t *blacklist = blacklist_load(opts.blacklist_filename);
    if (blacklist == NULL) {
        sshguard_log(LOG_ERR, "blacklist: could not open %s: %m",
                     opts.blacklist_filename);
        exit(66);
    }

    sshguard_log(LOG_INFO, "blacklist: blocking %u addresses",
                 (unsigned int)list_size(blacklist));
    block_list(blacklist);
}
