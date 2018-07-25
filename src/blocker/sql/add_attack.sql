-- Add attack from attacker ID
INSERT INTO attacks (attacker_id, service, score, time)
    VALUES (?, ?, ?, datetime('now'));
