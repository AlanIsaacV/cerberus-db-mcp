-- The fixture for the database-set criteria on this engine.
--
-- ledger is a second database owned by the same test role. It is what makes
-- CERBERUS_DB_<ALIAS>_DATABASES=testbed,ledger two working connections, and it is
-- the name list_databases has to report that no engine created — the templates and
-- `postgres` are all excluded, so without a database of our own the exclusion
-- assertion would be satisfied by an empty list.
--
-- It is owned by cerberus so that a test can create its own probe table in it, the
-- way every other fixture here works, rather than needing tables shipped from this
-- file.
CREATE DATABASE ledger OWNER cerberus;

-- The rest of this file exists so that the discovery statement can fail for lack
-- of permission at all.
--
-- On a stock cluster it cannot: pg_database is readable by PUBLIC, so every login
-- that can connect can read the whole list, and the "no permission" case the
-- sanitisation criterion asks about has no way to happen. So the default is taken
-- away and handed back to the ordinary test role only, leaving the role below as
-- the one that is refused.
--
-- Per database, and that is not a redundancy: pg_database is a shared table, but
-- its privileges live in each database's own pg_class row, so a REVOKE in one
-- database says nothing about the next. Both databases an alias here connects to
-- therefore get it, so that which of the two a test picks cannot change the answer.
CREATE ROLE cerberus_nocatalog LOGIN PASSWORD 'cerberus-test-pg-nocatalog';

\connect testbed
REVOKE SELECT ON pg_database FROM PUBLIC;
GRANT SELECT ON pg_database TO cerberus;

\connect ledger
REVOKE SELECT ON pg_database FROM PUBLIC;
GRANT SELECT ON pg_database TO cerberus;
