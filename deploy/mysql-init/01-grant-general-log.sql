-- The byte-identity acceptance criterion is asserted against MySQL's own
-- general_log, because that table records the statement the server actually
-- received rather than the statement this process believes it sent. Reading it
-- needs SELECT on a table in the mysql schema, which the test user does not have
-- by default.
--
-- This grant exists for the test container and nowhere else. Nothing in the
-- application reads the general log, and no production account needs this.
GRANT SELECT ON mysql.general_log TO 'cerberus'@'%';
FLUSH PRIVILEGES;
