-- Release block
UPDATE blocks SET blocked=false WHERE attacker_id=?;
