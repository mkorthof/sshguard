CREATE TABLE IF NOT EXISTS attackers(
    attacker_id INTEGER PRIMARY KEY,
    address TEXT UNIQUE NOT NULL,
    family INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attacks(
    attacker_id INTEGER,
    service INTEGER,
    score INTEGER,
    time DATE
);

CREATE TABLE IF NOT EXISTS blocks(
    attacker_id INTEGER,
    release_time DATE,
    blocked BOOLEAN,
    UNIQUE(attacker_id, release_time)
);
