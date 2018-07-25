-- Obtain attacker ID and whether it's already blocked
SELECT attacker_id, MAX(blocked) FROM attackers
    LEFT OUTER JOIN blocks USING (attacker_id) WHERE address=?;
