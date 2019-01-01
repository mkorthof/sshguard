const static char* sql_add_attack = {
    "-- Add attack from attacker ID\n"
    "INSERT INTO attacks (attacker_id, service, score, time)\n"
    "    VALUES (?, ?, ?, datetime('now'));\n"
};
sqlite3_stmt* stmt_add_attack;
const static char* sql_add_attacker = {
    "-- Assign attacker ID\n"
    "INSERT OR IGNORE INTO attackers (address, family) VALUES (?, ?);\n"
};
sqlite3_stmt* stmt_add_attacker;
const static char* sql_add_block = {
    "-- Add block against attacker ID\n"
    "INSERT INTO blocks (attacker_id, release_time, blocked)\n"
    "    VALUES (?, datetime(?, 'unixepoch'), 1);\n"
};
sqlite3_stmt* stmt_add_block;
const static char* sql_data = {
    "INSERT INTO attackers VALUES\n"
    "(1, '192.168.2.1', 4),\n"
    "(2, '192.168.2.2', 4),\n"
    "(3, '192.168.2.3', 4);\n"
    "\n"
    "INSERT INTO attacks VALUES\n"
    "(1, 100, 10, datetime(1000, 'unixepoch')),\n"
    "(2, 100, 10, datetime(1000, 'unixepoch')),\n"
    "(3, 100, 10, datetime(1000, 'unixepoch')),\n"
    "(1, 100, 10, datetime(1001, 'unixepoch')),\n"
    "(2, 100, 10, datetime(1001, 'unixepoch')),\n"
    "(1, 100, 10, datetime(1002, 'unixepoch')),\n"
    "(2, 100, 10, datetime(1002, 'unixepoch')),\n"
    "(1, 100, 10, datetime(2000, 'unixepoch')),\n"
    "(2, 100, 10, datetime(2000, 'unixepoch')),\n"
    "(1, 100, 10, datetime(2001, 'unixepoch')),\n"
    "(1, 100, 10, datetime(2002, 'unixepoch'));\n"
    "\n"
    "INSERT INTO blocks VALUES\n"
    "(1, datetime(1900, 'unixepoch'), false),\n"
    "(2, datetime(1900, 'unixepoch'), false),\n"
    "(1, datetime(2900, 'unixepoch'), true);\n"
};
sqlite3_stmt* stmt_data;
const static char* sql_get_cum_score = {
    "SELECT SUM(score) FROM attacks WHERE attacker_id=?;\n"
};
sqlite3_stmt* stmt_get_cum_score;
const static char* sql_get_id = {
    "-- Obtain attacker ID and whether it's already blocked\n"
    "SELECT attacker_id, MAX(blocked) FROM attackers\n"
    "    LEFT OUTER JOIN blocks USING (attacker_id) WHERE address=?;\n"
};
sqlite3_stmt* stmt_get_id;
const static char* sql_get_initial_blocks = {
    "-- Get initial blocks on startup\n"
    "SELECT address, family FROM blocks NATURAL JOIN attackers\n"
    "    WHERE blocked GROUP BY attacker_id;\n"
};
sqlite3_stmt* stmt_get_initial_blocks;
const static char* sql_get_releases = {
    "-- List blocks that should be released\n"
    "WITH release_tbl AS (\n"
    "    SELECT attacker_id FROM blocks WHERE blocked\n"
    "        GROUP BY attacker_id HAVING MAX(release_time) < datetime('now')\n"
    ") SELECT * FROM release_tbl NATURAL JOIN attackers;\n"
    "\n"
};
sqlite3_stmt* stmt_get_releases;
const static char* sql_get_score_since_last_block = {
    "-- Get score accumulated since last block or beginning of time\n"
    "-- slow but working version\n"
    "WITH last_blocks AS (\n"
    "    SELECT attacker_id, MAX(release_time) AS last_block\n"
    "        FROM blocks GROUP BY attacker_id\n"
    ") SELECT SUM(score) FROM attacks\n"
    "    LEFT JOIN last_blocks on attacks.attacker_id==last_blocks.attacker_id\n"
    "    WHERE (time > last_block OR last_block IS NULL)\n"
    "        AND attacks.attacker_id = ?;\n"
    "\n"
    "-- faster version?\n"
    "WITH reltime AS (\n"
    "    SELECT MAX(release_time) AS last_block FROM blocks WHERE attacker_id=2\n"
    ") SELECT * FROM attacks, reltime WHERE attacker_id=2 AND time > last_block;\n"
};
sqlite3_stmt* stmt_get_score_since_last_block;
const static char* sql_init = {
    "CREATE TABLE IF NOT EXISTS attackers(\n"
    "    attacker_id INTEGER PRIMARY KEY,\n"
    "    address TEXT UNIQUE NOT NULL,\n"
    "    family INTEGER NOT NULL\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS attacks(\n"
    "    attacker_id INTEGER,\n"
    "    service INTEGER,\n"
    "    score INTEGER,\n"
    "    time DATE\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS blocks(\n"
    "    attacker_id INTEGER,\n"
    "    release_time DATE,\n"
    "    blocked BOOLEAN,\n"
    "    UNIQUE(attacker_id, release_time)\n"
    ");\n"
};
sqlite3_stmt* stmt_init;
const static char* sql_release = {
    "-- Release block\n"
    "UPDATE blocks SET blocked=false WHERE attacker_id=?;\n"
};
sqlite3_stmt* stmt_release;
extern sqlite3* db;
static inline void db_prepare_all() {
    sqlite3_prepare_v2(db, sql_add_attack, -1, &stmt_add_attack, NULL);
    sqlite3_prepare_v2(db, sql_add_attacker, -1, &stmt_add_attacker, NULL);
    sqlite3_prepare_v2(db, sql_add_block, -1, &stmt_add_block, NULL);
    sqlite3_prepare_v2(db, sql_data, -1, &stmt_data, NULL);
    sqlite3_prepare_v2(db, sql_get_cum_score, -1, &stmt_get_cum_score, NULL);
    sqlite3_prepare_v2(db, sql_get_id, -1, &stmt_get_id, NULL);
    sqlite3_prepare_v2(db, sql_get_initial_blocks, -1, &stmt_get_initial_blocks, NULL);
    sqlite3_prepare_v2(db, sql_get_releases, -1, &stmt_get_releases, NULL);
    sqlite3_prepare_v2(db, sql_get_score_since_last_block, -1, &stmt_get_score_since_last_block, NULL);
    sqlite3_prepare_v2(db, sql_init, -1, &stmt_init, NULL);
    sqlite3_prepare_v2(db, sql_release, -1, &stmt_release, NULL);
}
static inline void db_finalize_all() {
    sqlite3_finalize(stmt_add_attack);
    sqlite3_finalize(stmt_add_attacker);
    sqlite3_finalize(stmt_add_block);
    sqlite3_finalize(stmt_data);
    sqlite3_finalize(stmt_get_cum_score);
    sqlite3_finalize(stmt_get_id);
    sqlite3_finalize(stmt_get_initial_blocks);
    sqlite3_finalize(stmt_get_releases);
    sqlite3_finalize(stmt_get_score_since_last_block);
    sqlite3_finalize(stmt_init);
    sqlite3_finalize(stmt_release);
}
