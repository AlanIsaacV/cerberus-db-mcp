# cerberus-db-mcp

cerberus-db-mcp is a gated, read-only Model Context Protocol server for MySQL,
PostgreSQL, and SQL Server. An authenticated Google identity must be on the
deployment's allowlist before it can reach a tool; the statement gate executes
no statement it cannot establish is a read, and each query is audited with the
calling identity.

SQL Server has no reproducible grading for this catalog surface: there is no
arm64 SQL Server image, so there is no CI container and no fixture. Its fixed
`search_schema` statement and three fixed `describe_table` statements have now
been run by hand against the real third-party deployment target, over the VPN,
from two integration tests: `internal/db/mssql_schema_integration_test.go`, which
drives the four statements straight through the executor — the search over the
real catalog, the schema-qualified description, and each bound in turn — and
`internal/mcp/mssql_sequence_integration_test.go`, which drives the whole agent
sequence over the real MCP transport with the real SDK client: `list_databases`,
`search_schema`, `describe_table`, and an `execute_query` whose `SELECT` is
assembled at run time from what `describe_table` had just returned, which is what
shows a description is enough on its own to query that table without a further
round trip. All four statements are valid T-SQL as shipped, all four returned
decoded results, and that login could read every one of the eight `sys.*` views
they touch. The bounds held there as they do elsewhere: each catalog read ran
inside a transaction that was rolled back whether it succeeded or failed, under
`LOCK_TIMEOUT` and the query deadline, every answer reported the byte budget it
was assembled against, and one cut by the row cap named `row_cap` with the cap's
own value beside it.

That run establishes the statements execute; it does not establish how they
behave under the load this surface exists for. The instance reached holds 54
tables and 528 columns in a single schema, so the byte budget never bound
anything there, and nothing measured on it says what a search or a description
costs on a schema large enough for that budget to matter. The measured sequence
cost 3332 bytes on the wire in total, 13% of the 25600-byte ceiling the sequence
test enforces — but nothing on that instance was truncated, so that total says
the bounds were never approached there, not that they hold when they bind. That
case is graded against the wide fixture on PostgreSQL and MySQL and on no SQL
Server, because no reachable SQL Server has a schema of that size. Nor is the
run repeatable by anyone else: those tests skip unless the runner has the VPN,
the credentials, and `CERBERUS_TEST_SQLSERVER_ALIAS` naming a configured alias,
and CI grades exactly the engines it graded before.

## Configuration

Copy the root `.env.example` to an untracked `.env` and fill in the required
values. Configuration is environment-only: no configuration file is read by the
process, and the `.env` file must not be committed. The deployment compose file
loads an `.env` beside it.

### Required

- `CERBERUS_DB_ALIASES`: comma-separated database aliases. Each alias must have
  the following five variables, replacing `<ALIAS>` with the alias upper-cased
  and with hyphens changed to underscores:
  `CERBERUS_DB_<ALIAS>_ENGINE` (`mysql`, `postgresql`, or `sqlserver`),
  `CERBERUS_DB_<ALIAS>_HOST`, `CERBERUS_DB_<ALIAS>_PORT`,
  `CERBERUS_DB_<ALIAS>_USER`, and `CERBERUS_DB_<ALIAS>_PASSWORD`.
- `CERBERUS_DB_<ALIAS>_DATABASES`: the comma-separated databases that alias
  exposes. Required on PostgreSQL and optional on MySQL and SQL Server, and it
  changes the names the agent uses — see "The databases an alias exposes" below.
  The singular `CERBERUS_DB_<ALIAS>_DATABASE` this replaced is now refused at
  startup; the same section says how to migrate.
- `CERBERUS_AUTH_GOOGLE_CLIENT_ID`: the Google OAuth client ID that issued the
  access tokens this deployment accepts.
- `CERBERUS_AUTH_ALLOWED_EMAILS`: the comma-separated verified Google email
  addresses allowed to reach a tool.
- `CERBERUS_AUTH_SEALING_SECRET`: the base64-encoded 32-byte master secret,
  generated outside this process; changing it invalidates every credential it
  issued.

### Defaulted or optional

- `CERBERUS_DB_<ALIAS>_TLS` is optional for each alias. When unset, it leaves
  the relevant driver's TLS default in force; accepted explicit values are
  `disable`, `require`, and `require-insecure`.
- `CERBERUS_DB_ROW_CAP` defaults to `1000`.
- `CERBERUS_DB_QUERY_TIMEOUT` defaults to `20s`.
- `CERBERUS_DB_TIMEOUT_GRACE` defaults to `5s`.
- `CERBERUS_DB_LOCK_TIMEOUT` defaults to `3s`.
- `CERBERUS_DB_CONNECT_TIMEOUT` defaults to `10s`.
- `CERBERUS_DB_MAX_CONNS` defaults to `4`.
- `CERBERUS_MCP_ADDRESS` defaults to `127.0.0.1:8080`. The deployment compose
  file deliberately overrides it with `0.0.0.0:8080` so cloudflared can reach
  the service on the shared Docker network.
- `CERBERUS_MCP_PATH` defaults to `/mcp`.
- `CERBERUS_MCP_SHUTDOWN_TIMEOUT` defaults to `30s`.

The process also refuses to start when a configured PostgreSQL alias has a
non-empty `PGSERVICE` or `PGSERVICEFILE`, or when a configured SQL Server alias
has a non-empty `MSSQL_USE_EPA`. Those are driver variables rather than service
configuration; remove them from this service's environment instead of letting a
driver silently decide connection behavior.

### The databases an alias exposes

`CERBERUS_DB_<ALIAS>_DATABASES` lists them, comma-separated, each name trimmed.
An empty element or the same name twice is refused at startup naming the alias
and the variable, rather than skipped: `a,,b` is a typo far more often than it is
a way of writing two databases.

Every listed database becomes a connection of its own, named
`<alias>.<database>`. So `CERBERUS_DB_CRM_DATABASES=sales,billing` gives the
agent the aliases `crm.sales` and `crm.billing`, and there is no alias `crm`. A
one-element list derives the same way, so `CERBERUS_DB_CRM_DATABASES=sales` is
the alias `crm.sales`. That is deliberate: keeping the parent's name for a single
database would mean that adding a second one silently renames the first alias,
and a renamed alias is something an agent finds out about by being told the alias
it just used is unknown. The dot is what makes a derived name safe — a declared
alias may hold only letters, digits, hyphens and underscores, so nothing derived
here can collide with a name an operator wrote in `CERBERUS_DB_ALIASES`.

Leaving the variable unset is a different configuration, and the engines do not
agree about it:

- **MySQL and SQL Server accept it.** The alias stays a single connection under
  exactly the name declared, with no database configured. On MySQL that means the
  session has no default schema, so every table reference has to name its
  database; on SQL Server the login's own default database applies. On both, the
  login reads whatever it has permission for through a qualified name, and
  `list_databases` is how the agent finds out what to qualify with.
- **PostgreSQL refuses to start** and names the alias and the variable. A
  connection there is bound to one database by the protocol and there is no
  cross-database query, so a connection with no database has nothing it could
  read — and the driver supplies no default of its own, which would leave the
  server quietly defaulting the database to the user name.

#### Migrating from `CERBERUS_DB_<ALIAS>_DATABASE`

The singular variable is gone. Nothing reads it, and a configuration that still
sets it is refused at startup with an error naming the alias, the old variable
and the new one — including an `.env` that worked before this change, so a
deployed Pi needs the edit before its next `docker compose up -d`. Rename it and
keep the value: `CERBERUS_DB_CRM_DATABASE=sales` becomes
`CERBERUS_DB_CRM_DATABASES=sales`. The alias the agent names then changes from
`crm` to `crm.sales`, so anything holding the old name — a saved prompt, a note
in a client — changes with it.

Refusing rather than tolerating the old spelling is the point. Ignored, it would
give a MySQL alias a working connection to no database at all and no hint that
the name in it was never read, and it would tell a PostgreSQL operator that a
variable is missing while they are looking at one they had set.

### What the list restricts, and on which engine

**On PostgreSQL the list is a boundary.** Each connection can reach only its own
database, cross-database queries do not exist there, and a database that is not
on the list has no connection and no alias — so there is nothing for the agent to
name.

**On MySQL and SQL Server the list is not a boundary.** It decides which
connections exist and what `list_databases` reports, and it does not prevent a
read of a database that is not on it. The gate refuses `USE`, but nothing
restricts a qualified table reference: `SELECT * FROM otherdb.tbl` on MySQL and
`SELECT * FROM otherdb.dbo.tbl` on SQL Server are approved and return rows
whenever the login in `CERBERUS_DB_<ALIAS>_USER` has permission on `otherdb` —
whether or not `otherdb` is on the list, and whether or not the alias has a list
at all. What bounds what the agent can read on those two engines is that login's
own database permissions, so grant it only what it should be able to read; the
list is ergonomics and naming, not enforcement. Teaching the gate to refuse a
reference outside the list is separate work and has not been done.

### Finding out what exists

An operator configuring this service often does not know which databases are on a
host, and the agent never does. The `list_databases` tool answers that question
for one alias: it runs a fixed per-engine metadata statement on that alias's
existing connection — through the same gate, the same row cap and the same time
limit as `execute_query`, opening no connection and caching nothing — and returns
the names that come back with the engine's own system databases removed. Being
capped like any other result, it reports whether the cap cut the list off. What it
returns are database names and not aliases: `execute_query` still only accepts an
alias `list_connections` gave.

- MySQL runs `SHOW DATABASES`, excluding `information_schema`, `mysql`,
  `performance_schema` and `sys`.
- PostgreSQL runs `SELECT datname FROM pg_database WHERE NOT datistemplate AND
  datallowconn ORDER BY datname`, excluding `postgres`, `template0` and
  `template1`.
- SQL Server runs `SELECT name FROM sys.databases ORDER BY name`, excluding
  `master`, `model`, `msdb` and `tempdb`.

The answer is what exists, not what is reachable, and how far the two diverge
depends on the engine. `SHOW DATABASES` silently omits the schemas the MySQL
login has no privilege on, with no error and no indication that anything was
filtered — so a login with no grants and a server with no databases produce the
same empty list. `sys.databases` is filtered by SQL Server's metadata
visibility, which is close to but not the same as access: a database whose name
is visible but whose access has been revoked still appears, and the agent
discovers that by being refused when it queries. `pg_database` is readable by
everyone, so on PostgreSQL the list can name databases this login could not open
at all.

PostgreSQL has a second gap worth knowing before reading a result there: a
database on that list which is not in the alias's `CERBERUS_DB_<ALIAS>_DATABASES`
has no connection and no alias, so the agent cannot query it even though the tool
just named it. Making it reachable means adding it to the variable and
restarting. Discovering and connecting to PostgreSQL databases automatically is
later work.

Because startup does not touch a database, a login that cannot run its engine's
discovery statement is not a startup failure. It surfaces on the first
`list_databases` call, as the same agent-facing error any other failed call
returns — naming no credential, host, port or username — and it is audited like
any other tool call.

### Searching one database's schema

`list_databases` says what exists on a server; `search_schema` says what is inside
the one database an alias is bound to. It takes that alias and a plain
case-insensitive substring — not a `LIKE` expression, because `%` and `_` are
searched literally — binds that substring to a fixed per-engine catalog statement,
and returns one entry per matching table with the matching columns inside it, each
carrying its type and whether it accepts NULL. A pattern shorter than two
characters is refused before a connection is borrowed. The search never crosses a
database boundary: a call answers about the alias's own database and nothing else.

Its results are bounded by bytes as well as by rows. `CERBERUS_DB_ROW_CAP` bounds
the flat catalog rows before they are grouped, and a byte budget then bounds the
grouped answer. `truncation` says exactly which result the agent holds: `none`
means neither bound cut it, `row_cap` means the catalog read stopped before
grouping, and `byte_budget` means the assembled answer ran out of room. A
non-`none` result is the beginning of what matched, and a table listed in one can
hold only part of its matching columns, so the remedy is to search again with a
longer or more specific substring rather than to page. The row cap alone would
not make "no pattern returns the whole schema"
true: every table in a schema may carry one column name in common — an audit
timestamp, a tenant id — so a two-character substring can match a few hundred
catalog rows, far below the default cap of 1000, and still group into an entry for
every table in the database.

Each table says for itself whether its own column list is complete, in
`columns_truncated`. That field is what keeps an empty `columns` readable: where it
is false, an empty list is the answer that the table name matched and none of its
columns did; where it is true, the columns listed are only the ones that fit, and
an empty list says nothing about that table at all. The budget stops at a column
rather than at a table boundary, and the table it stopped in is kept rather than
dropped — a search for a column name that matches 250 columns of one wide table
would otherwise answer with no tables at all — so the marked entry is the last one
in a truncated result, holding the part of its column list that fit.

The byte budget is a constant in the code and deliberately not a `CERBERUS_DB_*`
setting. The row cap is configurable because it trades completeness against load
on somebody else's server, and that trade belongs to the operator who runs against
it. The byte budget trades completeness against the agent's context, which is a
property of this surface rather than of a deployment — and a bound an operator can
raise is a bound that can be raised back past the point where a whole catalog fits
inside it again.

What one call costs is measured rather than derived from the row cap. The
integration job in `.github/workflows/ci.yml` runs the measurement over the wide
test fixture on PostgreSQL and MySQL and prints it under "search_schema result
size" in the job summary: the bytes of the whole MCP result, including the
duplicate JSON text block the SDK sends beside the structured content, both for a
search narrow enough to name one table and for the broadest pattern the tool
accepts. The same test fails if the first exceeds 4 KB or the second 20 KB.

### Describing one table

`describe_table` takes an alias and a table name, plus an optional schema. It
returns every matching table's columns with type and nullability, its ordered
primary-key columns, and its secondary indexes with their key columns in order
and their uniqueness. Omitting the schema can return one description per schema
that holds a table with that name; it does not make a database name into an
alias, and the call never crosses the selected alias's database.

Like `search_schema`, its answer is bounded by the row cap and by the fixed byte
budget, and `truncation` names the bound that cut a short answer: `none`,
`row_cap`, or `byte_budget`. The primary key and index detail are retained ahead
of columns, so only the tail of the column list can be short; search again with
`search_schema` for a specific column name when that detail is needed.

The catalog reads are intentionally asymmetric. PostgreSQL reads `pg_catalog`
and SQL Server reads `sys.*`, neither of which filters the column list by
privilege. MySQL reads `information_schema`, which does: a MySQL login without
permission on a column receives a short column list with no error.

## Raspberry Pi deployment

This deployment has not been tested on the Raspberry Pi. Its operating system,
Docker and Compose versions, and whether its required external network exists
cannot be established from this repository.

Copy `deploy/compose.yaml` and a completed `.env` into the same stack directory
on the Pi. From that directory, deploy the published image with:

```sh
docker compose pull && docker compose up -d
```

The compose file runs one `cerberus-db-mcp` service from the ghcr image, sets
starting `mem_reservation` and `mem_limit` values of `128m` and `256m`, and
restarts it unless stopped. Those are starting points, not measurements from
this Pi. It publishes no host ports. Instead, it joins the externally managed
Docker network named `homelab`; that network must already exist before `docker
compose up -d` can succeed.

To roll back, pin an older release tag such as `:vX.Y.Z` in the compose file's
`image:` value, then repeat `docker compose pull && docker compose up -d`.

The external SQL Server is reachable through a VPN that must be up on the Pi,
not on a laptop. Startup does not ping databases, so the service can start while
the VPN is down and only fail when the first query attempts to connect.

### Cloudflare Tunnel

`cloudflared` is operator-managed in its own container and is intentionally not
defined by this repository's compose file. It must join the same `homelab`
network and route the public hostname to the application container:

```yaml
ingress:
  - hostname: <public-hostname>
    service: http://cerberus-db-mcp:8080
```

### Interpreting 403 responses

An allowlist refusal returns `forbidden: this identity is not allowed on this
server` and writes an application log record with
`auth_refusal=identity_allowlist`. Add the verified address to
`CERBERUS_AUTH_ALLOWED_EMAILS` when that is the intended caller.

The MCP SDK has a separate Host-header refusal, but it cannot occur in this
container topology because the service binds `0.0.0.0:8080`, not a loopback
address. If it does ever appear, its body is `Forbidden: invalid Host header
"..."` and the codebase writes no log line at all. That absence is the way to
tell it apart from an identity-allowlist refusal. The SDK rule remains relevant
when running the binary directly with its loopback default.

## Health and logs

`GET /healthz` returns `200` without authentication and does not touch a
database. The compose file deliberately has no healthcheck: the distroless image
has neither a shell nor `wget`, and respawning a probe at an interval would spend
CPU and RSS that the 2GB Pi needs for the workload. Docker can therefore report
the container as `running` even when the process is wedged. `/healthz` is only
as useful as an external poller, and none is configured here yet.

Both the application log and the audit stream are zerolog JSON on stdout. Audit
events carry `stream=audit`, the verified caller email in `Identity`, and the
Google subject in `Subject`; container stdout therefore holds personal data.
Permissions, retention, and rotation are the operator's responsibility to
configure in Docker on the server.

### Measure memory before tuning it

The compose memory reservation and limit are starting points, not measured
results from this Pi. The reservation is the floor Docker tries to keep
available to the container under host memory pressure; the limit is the ceiling
beyond which the container is OOM-killed. On the Pi, first take a
point-in-time measurement:

```sh
docker stats --no-stream "$(docker compose ps -q cerberus-db-mcp)"
```

Then keep `docker stats "$(docker compose ps -q cerberus-db-mcp)"` running while
an authenticated client performs representative queries, including the largest
ordinary result and a slow query that exercises the configured bounds. Record
the observed memory under both idle and query load, then adjust both values
together: keep the reservation comfortably below observed steady-state usage
and the limit above the observed peak. The limit must always stay above the
reservation—Docker refuses the compose file otherwise. If the service has safe
headroom, lower the pair in `deploy/compose.yaml`; if it approaches the ceiling
during the expected workload, raise the pair only after accounting for the
other services on the 2GB Pi. Apply the chosen values with `docker compose up
-d` and repeat the observation under the same workload.

## Development

Run the unit suite without any database containers:

```sh
go test ./...
```

The integration suite is behind the `integration` build tag. Start the MySQL and
PostgreSQL test containers from `deploy/compose.test.yaml`, configure their
aliases as described in `.env.example`, then run:

```sh
docker compose -f deploy/compose.test.yaml up -d
go test -tags integration -race -timeout 20m -p 1 ./...
```

Each engine's fixtures come from the SQL files in `deploy/postgres-init` and
`deploy/mysql-init`, including the generated wide schema fixture, and both images
run those only while initialising an empty data directory. Containers that already
existed before those files changed therefore lack the second database, the
low-privilege PostgreSQL role, or the wide schema the integration tests need, and
`up -d` will not add them. Recreate them once:

```sh
docker compose -f deploy/compose.test.yaml down -v
docker compose -f deploy/compose.test.yaml up -d
```

SQL Server has no container coverage because no arm64 image is available, so it
has no fixture and CI runs nothing against it. It is exercised only against a
real instance, by tests that skip when there is no such instance: the SQL Server
tests under `internal/db`, and `internal/mcp/mssql_sequence_integration_test.go`,
which runs the four-call agent sequence over the real transport and reports what
each call cost on the wire. `internal/db/mssql_integration_test.go` takes
whichever `sqlserver` alias is configured; the catalog tests in
`internal/db/mssql_schema_integration_test.go` and the sequence test take only
the alias `CERBERUS_TEST_SQLSERVER_ALIAS` names, because more than one alias is
normally configured and an assertion about a catalog is an assertion about one
server specifically. That variable has no default, so those tests skip until
somebody sets it. `CERBERUS_TEST_REQUIRE_ENGINES` in CI stays `postgresql,mysql`
and deliberately does not name this engine: no runner can reach an instance, so a
requirement it cannot satisfy would fail every run.

The catalog statements have been run that way against the third-party deployment
target and they work there, as the top of this file records. Nothing about that
run is repeatable from this repository alone — it needs the VPN and the
credentials — and because there is no fixture, what it asserts is shape rather
than content: the statements parse and run, rows decode, indexes group, key
columns keep their ordinal order, a bound that cut an answer says which one, and
the `SELECT` the sequence test writes out of a `describe_table` answer alone runs
and returns rows. Every name those assertions need is discovered from the server
at runtime, so no identifier of that instance is written down here.

Two things that run did not cover. A several-hundred-table schema, which that
instance is not. And the byte budget under a load that reaches it: on a
single-schema database the unqualified `describe_table` returns exactly what the
schema-qualified form returns, so the argument form that would produce the most
entries is degenerate there, and the only call that would have spent the budget
is a deliberately broad search against somebody else's production server. What
the wire measurement does say about that budget is how little room sits above it:
each of the four calls crossed the wire at 2.4 to 4.4 times its own payload,
because the SDK sends the payload twice, so one answer that spent the whole byte
budget would cost some 19 to 20 KB and two of them would pass the 25600-byte
ceiling between them.
