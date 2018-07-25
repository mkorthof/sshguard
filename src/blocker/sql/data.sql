INSERT INTO attackers VALUES
(1, '192.168.2.1', 4),
(2, '192.168.2.2', 4),
(3, '192.168.2.3', 4);

INSERT INTO attacks VALUES
(1, 100, 10, datetime(1000, 'unixepoch')),
(2, 100, 10, datetime(1000, 'unixepoch')),
(3, 100, 10, datetime(1000, 'unixepoch')),
(1, 100, 10, datetime(1001, 'unixepoch')),
(2, 100, 10, datetime(1001, 'unixepoch')),
(1, 100, 10, datetime(1002, 'unixepoch')),
(2, 100, 10, datetime(1002, 'unixepoch')),
(1, 100, 10, datetime(2000, 'unixepoch')),
(2, 100, 10, datetime(2000, 'unixepoch')),
(1, 100, 10, datetime(2001, 'unixepoch')),
(1, 100, 10, datetime(2002, 'unixepoch'));

INSERT INTO blocks VALUES
(1, datetime(1900, 'unixepoch'), false),
(2, datetime(1900, 'unixepoch'), false),
(1, datetime(2900, 'unixepoch'), true);
