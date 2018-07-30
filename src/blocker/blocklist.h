#pragma once

#include <stdbool.h>

#include "attack.h"

unsigned int fw_block_subnet_size(int inet_family);

bool blocklist_contains(attack_t);
void blocklist_add(attacker_t *);
void blocklist_init();

void blacklist_load_and_block();

void unblock_expired(bool release);

void fw_block(const char address[static 1], int kind);
void fw_release(const char address[static 1], int kind);
