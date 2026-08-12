-- The image's POSTGRES_USER is a superuser and cannot give that up — the
-- bootstrap role must keep it. A superuser also bypasses every privilege check,
-- which makes one of the error classes the sanitisation criterion asks for
-- impossible to provoke: there is no object a superuser is denied.
--
-- So the account the tests connect as is created here instead, with login rights
-- and nothing else. It owns its own database, which is what lets the containment
-- tests create their probe tables, and it can see its own sessions in
-- pg_stat_activity, which is all the observation those tests do. What it cannot do
-- is read pg_authid — and that refusal is the point.
CREATE ROLE cerberus LOGIN PASSWORD 'cerberus-test-pg';
CREATE DATABASE cerberus OWNER cerberus;
