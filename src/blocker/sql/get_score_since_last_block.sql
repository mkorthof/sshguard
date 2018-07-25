-- Get score accumulated since last block or beginning of time
-- slow but working version
WITH last_blocks AS (
    SELECT attacker_id, MAX(release_time) AS last_block
        FROM blocks GROUP BY attacker_id
) SELECT SUM(score) FROM attacks
    LEFT JOIN last_blocks on attacks.attacker_id==last_blocks.attacker_id
    WHERE (time > last_block OR last_block IS NULL)
        AND attacks.attacker_id = ?;

-- faster version?
WITH reltime AS (
    SELECT MAX(release_time) AS last_block FROM blocks WHERE attacker_id=2
) SELECT * FROM attacks, reltime WHERE attacker_id=2 AND time > last_block;
