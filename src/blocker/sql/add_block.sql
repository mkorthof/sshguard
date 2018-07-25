-- Add block against attacker ID
INSERT INTO blocks (attacker_id, release_time, blocked)
    VALUES (?, datetime(?, 'unixepoch'), 1);
