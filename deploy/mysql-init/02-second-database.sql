-- The fixture for the database-set criteria on this engine.
--
-- ledger is a second database on the same server, reachable by the same login as
-- testbed. Two things need it: a MySQL alias with no CERBERUS_DB_<ALIAS>_DATABASES
-- has to be shown reading two databases through qualified names in one session, and
-- list_databases has to report a database no engine created — every name it excludes
-- is one MySQL made itself.
--
-- It is created here rather than by a test because the test account has no CREATE
-- privilege outside its own schema, and the entrypoint runs this file as root. The
-- privileges are the account's own so that a test can create and drop its probe
-- table in it, which is how every other fixture in this package works; SHOW
-- DATABASES needs some privilege on a schema to report it at all, and this is also
-- what makes the schema visible there.
CREATE DATABASE ledger;
GRANT ALL PRIVILEGES ON ledger.* TO 'cerberus'@'%';
FLUSH PRIVILEGES;
