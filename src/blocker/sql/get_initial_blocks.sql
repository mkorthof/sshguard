-- Get initial blocks on startup
SELECT address, family FROM blocks NATURAL JOIN attackers
    WHERE blocked GROUP BY attacker_id;
