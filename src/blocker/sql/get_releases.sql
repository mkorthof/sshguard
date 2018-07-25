-- List blocks that should be released
WITH release_tbl AS (
    SELECT attacker_id FROM blocks WHERE blocked
        GROUP BY attacker_id HAVING MAX(release_time) < datetime('now')
) SELECT * FROM release_tbl NATURAL JOIN attackers;

