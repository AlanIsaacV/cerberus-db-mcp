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
values. Configuration is environment-only: the one file the process reads is the
gate overlay `CERBERUS_MCP_GATE_OVERLAY` names, which holds gate rules and never a
credential, and the `.env` file must not be committed. The deployment compose file
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
- `CERBERUS_AUTH_GOOGLE_CLIENT_ID`: the public Google OAuth client ID that
  issued the access tokens this deployment accepts and is paired with the
  client secret this server uses for its own authorization-code exchange.
- `CERBERUS_AUTH_GOOGLE_CLIENT_SECRET`: the paired Google OAuth client secret.
  It is a real secret; whitespace is refused rather than trimmed, including a
  trailing newline pasted with the value.
- `CERBERUS_AUTH_ALLOWED_EMAILS`: the comma-separated verified Google email
  addresses allowed to reach a tool.
- `CERBERUS_AUTH_SEALING_SECRET`: the base64-encoded 32-byte master secret,
  generated outside this process; whitespace is refused rather than trimmed,
  and changing it invalidates every credential it issued.
- `CERBERUS_AUTH_PUBLIC_BASE_URL`: the public HTTPS origin at which clients and
  Google reach this process. It cannot be detected: the process binds no host
  port and terminates no TLS, and cloudflared reaches it through an external
  Docker network from a container configured outside this repository. It must be
  an absolute `https` URL with no query, fragment or userinfo; a trailing slash
  is removed, and whitespace is refused rather than trimmed. The callback to
  register in Google is this value with `/authorize/callback` appended.
- `CERBERUS_AUTH_CLIENT_REDIRECT_URIS`: the comma-separated redirect URIs this
  server's authorization endpoint will send an authorization code to. With no
  dynamic client registration, this list is the only client registry this design
  has, and a request naming a redirect URI outside it is refused before Google
  is contacted. Matching is exact string equality against an entry as written: a
  different host, a different scheme, an appended path, a trailing segment on an
  accepted prefix, or a trailing slash the entry does not have are all refusals,
  so a URI one character away from the one the client sends fails here rather
  than against a browser. Entries are not trimmed and whitespace anywhere in one
  is refused — including the space in `a, b` and the empty element a trailing
  comma leaves behind, neither of which this list forgives the way
  `CERBERUS_AUTH_ALLOWED_EMAILS` does. An absent, empty, or all-blank value
  refuses to start and names the variable, because an empty registry is a
  deployment mistake rather than an endpoint deliberately admitting no client.

The server, not the connecting MCP client, holds the Google client secret and
performs the Google authorization-code flow. It is an OAuth 2.1 authorization
server in its own right, in front of Google: it publishes three discovery
documents, issues its own credentials at `/token`, and renews them without a
browser — see "Connecting an MCP client" below. What it does not have is dynamic
client registration: `CERBERUS_AUTH_CLIENT_REDIRECT_URIS` is the whole client
registry, and a client's redirect URI has to be listed there before it can
connect.

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
- `CERBERUS_MCP_LOG_LEVEL` defaults to `info`; accepted values are `debug`,
  `info`, `warn`, and `error`.
- `CERBERUS_MCP_GATE_OVERLAY` is optional. Empty or unset, the gate runs the
  ruleset embedded in the binary and nothing else; set, it is the path of an
  overlay file applied on top of it — see "Gate overlay" below.

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

### What `execute_query` returns

`execute_query` takes an alias and one statement and answers with a JSON object:

```json
{
  "columns": ["id", "holder", "opened_at"],
  "rows": [[1, "Ana", "2026-10-07T12:34:56.789-06:00"]],
  "truncated": false,
  "truncation": "none",
  "row_cap": 1000,
  "byte_budget": 32768
}
```

- `columns` names the columns in the order their values appear in each row.
- `rows` holds one array per row, aligned with `columns` and in the order the
  statement returned them. Values are encoded by class:
  - NULL is `null`, a boolean the driver decodes as one is `true` or `false`
    (MySQL's `BOOLEAN` is an integer), and integers and finite floats are JSON
    numbers.
  - A decimal (`NUMERIC`, `DECIMAL`) is a string holding its exact digits, such
    as `"123456789012345678901234.56789"`, so no client parser rounds it.
  - A date or time is an RFC 3339 string with the fractional seconds the value
    carries, in the offset the driver decoded rather than converted to UTC.
  - A float JSON cannot express is the string `"NaN"`, `"Infinity"` or
    `"-Infinity"`.
  - Text is a string. A byte sequence that is not valid UTF-8 is an object with a
    single key, `{"$base64": "//79"}`; one that is valid UTF-8 arrives as text.
- `truncation` says which bound cut the answer: `none` means every row the
  statement returned is here; `row_cap` means the statement had more rows than
  `row_cap`; `byte_budget` means the next row would have taken the answer past
  `byte_budget` bytes. When both bounds were reached it is `byte_budget`, the one
  that cut what the agent holds.
- `truncated` is `true` exactly when `truncation` is not `none`. It is kept for
  clients written before `truncation` existed.
- `row_cap` is `CERBERUS_DB_ROW_CAP`, and `byte_budget` is 32768.

The byte budget is charged against the whole assembled result as JSON —
`columns`, `rows` and the fixed fields included — and each row is measured as it
is encoded on the wire. The fixed fields are priced as the answer will carry
them: a result that fits whole under its own `truncation`, `none` or `row_cap`,
is returned whole with that label. Only one that does not is cut, and then the
fields are priced as `byte_budget` and rows are kept in order until the next one
would not fit, so a cut answer is always a prefix of whole rows and never part of one; a first
row that alone exceeds the budget yields no rows and `truncation: "byte_budget"`.
The remedy for a cut answer is to name fewer or narrower columns, filter, or
aggregate rather than to page. Like the schema tools' budget, it is a constant in
the code and not a setting, and there is no argument that moves either bound.

What a client receives is about twice that: the SDK sends a typed result both as
`structuredContent` and as a duplicate JSON text block, as the MCP specification
asks of a tool with structured output, so one answer at the budget costs a
direct client about 64 KB. A client that reads only one of the two copies pays
the budget once.

A refused or failed statement comes back as an error result whose text is one of
a fixed set of sentences; the engine's own message never reaches the agent. One
refusal carries more: when the statement names a table or column that does not
exist on PostgreSQL or MySQL, the sentence is followed by the identifier as the
statement wrote it and, when the database's catalog holds close names, up to
three of them:

```text
the statement names a table, view or column this database does not have. Missing: "cardz". Similar: cards.
```

The text is the sentence, then `. Missing: "` and the identifier and `".`, then,
only when there are similar names, ` Similar: ` and the names separated by `, `
and ended by `.`. Nothing in it is escaped. The identifier is exactly a
substring of the statement, with a delimited identifier's own delimiters
(`"…"`, `` `…` ``, `[…]`) removed, so `"Cardz"` is named `Missing: "Cardz".`. A
qualified name written unquoted and without spaces, such as `c.holdr`, is named
as written; any other qualified name is named by its last part alone. An
identifier is named only when it contains no `"`, `'`, `` ` ``, `[`, `]`, `\`,
`,`, whitespace, control or other non-printing character, and no `.` except
between the parts of a qualified name; one that would is not named at all and
the refusal is the bare sentence. A client can therefore read the identifier up to the next `"`. The
similar names follow the same rule with no `.` at all, so splitting what follows
`Similar: ` on `, ` after dropping the final `.` recovers them.

The engine's message never decides what is shown; it only says which identifier
of the statement to look for. The statement is read with the engine's rules for
string literals, comments and delimited identifiers. Where a session setting
could change those rules the text is taken as a literal, never as an identifier,
so `"…"` is never searched on MySQL or SQL Server; MySQL's `--` is taken as a
comment even without the space MySQL requires after it. A statement that cannot
be read with certainty (an unterminated literal or comment, a backslash inside a
MySQL string literal or inside a PostgreSQL one not written `E'…'`, a MySQL
`/*!` comment) gets the bare sentence.

On PostgreSQL the identifier is the one at the character position the engine
reports, and it is named only when it matches the name the engine gives, part by
part from the end, ignoring case for an unquoted part and exactly for a
delimited one. When PostgreSQL reports no position into the statement — the
missing name was met inside server-side code, such as the body of a function the
statement calls, and the engine locates it in that code's own text instead — the
refusal is the bare sentence and no catalog read is made, even when the
statement happens to contain the same identifier. MySQL and SQL Server report no
position at all, so there the name the engine gives is matched the
same way against every identifier in the statement outside literals and
comments, so MySQL's `Table 'shop.cardz' doesn't exist` for a statement that
wrote `cardz` names `cardz`, not the database. When several identifiers match
and were written differently, only their common last part is named. When they
do not agree on it, when nothing matches, or when the engine's name holds a
character the rule above excludes (`Unknown column 'it's'`), the refusal is the
bare sentence. A name that occurs only inside a
string literal or a comment is never named.

The similar names come from the catalog of the database the alias is
bound to. For a missing table they are table and view names. For a missing
column they are first the column names of the tables the statement reads, when those
can be identified: for a qualified column such as `c.holdr`, the one table the
qualifier names, directly or through its alias; for an unqualified one, every
table after a `FROM` or `JOIN`. A table the statement names without a schema
stands for the table of that name in any schema of the database, or on MySQL in
the alias's database. When that cannot be told — a subquery, a table
function or a common table expression among the sources, an alias that names
more than one table, or no table at all — the column names of the whole database
are used instead. When the statement's tables were identified and none of their
columns is close enough, a second read takes the column names of the whole
database, so `a.batch_cod` on a table without it is still offered `batch_code`
from another table. Each read considers names whose length is within three of the
missing one and that share its first or last letter, at most 1000 of them
nearest in length first whatever `CERBERUS_DB_ROW_CAP` is, and ranks them by
edit distance; up to three
close enough are offered. Each goes through the gate and runs under the same
statement deadline as any other read. When a read fails, or the alias is not
bound to one database, the refusal goes out without `Similar:`; a failed read of
the statement's tables is not followed by the whole-database one. A missing
function, schema or database keeps the bare sentence. SQL Server's invalid
object and column names (errors 208 and 207) go through the same path, though no
SQL Server run has exercised it.

### Gate overlay

The statement gate's rules are embedded in the binary; that set is the baseline.
`CERBERUS_MCP_GATE_OVERLAY` names a JSON file applied on top of it, which is how
an exception to the gate is made by configuration rather than by publishing a
release. An overlay is the only input that can widen the gate: it can remove a
baseline rule, add a safe function, or raise `max_statement_bytes`. It is
therefore the operator's alone. No MCP tool and no HTTP route reads it, changes
it, or reloads it, and every load is logged.

The format is strict JSON. `version` must be `1`, an unknown field is an error,
and every other field is optional:

- `safe_functions` adds groups of function names, each group with `names`, an
  optional `engines` list (`mysql`, `postgresql`, `sqlserver`; empty means all
  three), and a `reason`. A name called as a function and absent from the
  allowlist holds the statement as `needs-approval`, and `execute_query` has no
  approval path, so a function the agent needs to call has to be named here.
- `remove_safe_functions` takes names off the baseline allowlist.
- `read_statements`, `forbidden_statements`, and `forbidden_functions` add rules,
  each with `id`, `match`, `reason`, and an optional `engines` list.
- `remove_rules` drops baseline rules by ID. An ID that does not exist is an
  error rather than a no-op. Removing an ID and adding a rule with the same ID
  replaces that rule.
- `non_function_keywords` adds words that may be followed by `(` without that
  being a function call.
- `max_statement_bytes` replaces the baseline's bound. It cannot go below `4096`.
- `notes` is free text for whoever reviews the file.

The merged result is validated whole before it takes effect. In particular, a
safe function whose name is also a forbidden keyword is refused unless that
keyword's rule carries a `safe_as_function` argument; when it does, the name
lets that keyword through when it is called as a function, and the load event
lists the declaration under `exemptions`.

To let the agent read two SQL Server user table-valued functions:

```json
{
  "version": 1,
  "safe_functions": [
    {
      "engines": ["sqlserver"],
      "names": ["dbo.fn_tblsaldosclientes", "dbo.fn_operacionesporcumplir"],
      "reason": "user table-valued functions the login may read, reviewed for an investigation"
    }
  ]
}
```

Names are written in lowercase and match case-insensitively. A schema-qualified
name matches only that same qualification: `dbo.fn_tblsaldosclientes` allows
`dbo.fn_tblSaldosClientes(...)` and `[dbo].[fn_tblSaldosClientes](...)`, but not
the bare `fn_tblSaldosClientes(...)` nor the database-qualified
`dbOyD.dbo.fn_tblSaldosClientes(...)`. Name each form the agent will write.

#### What each load logs

Startup and every reload write one event to the application log with
`trigger` (`startup` or `reload`), `overlay_configured`, `overlay_path`, a `diff`
against the baseline, and `exemptions`, the `safe_as_function` declarations in
force. The event carries `"level":"info"`, but `CERBERUS_MCP_LOG_LEVEL` does
not suppress it: at `warn` or `error` every load is still written. Its message is `gate ruleset loaded: no overlay is configured, so the
baseline is in force` or `gate ruleset loaded: the overlay was applied on top of
the baseline`. The `diff` always carries every category, empty when nothing
changed:

- `rules_added` and `rules_removed`, each entry with its `id`, `kind`
  (`read_statement`, `forbidden_statement`, or `forbidden_function`), `match`,
  `engines`, `prefix`, `safe_as_function`, and `reason`. `engines` always lists
  the engines the rule applies to; a rule declared without `engines` is written
  with all three;
- `rules_replaced`, each entry with its `id` and the rule as it is in the
  baseline under `baseline` and as it is now under `in_force`, both with the
  fields above other than `id`. A replacement that narrows a forbidden rule's
  `engines` stops forbidding it on the engines it dropped, and shows here as
  `engines` differing between the two;
- `safe_functions_added` and `safe_functions_removed`, keyed by engine;
- `non_function_keywords_added`;
- `max_statement_bytes_changed`, `null` unless the bound differs, and otherwise
  `baseline` and `in_force`.

An overlay of `{"version":1}` produces an empty diff.

At startup, a configured overlay that is missing, unreadable, malformed, or
fails validation stops the process before it listens. The log then reads
`cerberus-db-mcp is exiting on an error` with the error `gate overlay "<path>"
from CERBERUS_MCP_GATE_OVERLAY could not be loaded: <reason>`, and the process
exits `1`. It never falls back to the baseline.

#### Reloading and returning to the baseline

`SIGHUP` re-reads the file at the same path and swaps the ruleset in place,
without a restart and without dropping a session; see "Raspberry Pi deployment"
below for the command. A reload that fails for any of the startup reasons
leaves the previous ruleset entirely in force and writes one error event,
`gate overlay rejected on reload; the previous ruleset remains in force`, with
`overlay_path`, `error`, and `previous_ruleset_in_force: true`. A `SIGHUP` with
no overlay configured changes nothing and writes a warning saying so. A changed
path is not picked up by a reload; it takes a restart.

To return to the baseline, replace the file's content with `{"version":1}` and
reload, or empty `CERBERUS_MCP_GATE_OVERLAY` and restart. Deleting the file does
not: a configured overlay that is missing is rejected on reload and refuses the
next startup.

## Connecting an MCP client

This server signs a client in once. It runs the Google flow itself, and hands the
client a credential pair of its own, so a connected client does not go back
through a browser every hour the way it does when it points its own OAuth
straight at Google.

The reason it has to work this way is narrow: Google issues a refresh token only
when the authorization request carries `access_type=offline`, and no MCP client
sends that. This server sends it, keeps Google's refresh token sealed inside the
credential it gives the client, and spends it on the client's behalf at every
renewal.

### What is served

Everything below is answered without authentication, beside the MCP endpoint,
which is not:

| Path | What it is |
| --- | --- |
| `/.well-known/oauth-protected-resource` | RFC 9728 document naming this server's MCP endpoint as the resource and this server as its authorization server |
| `/.well-known/oauth-protected-resource<CERBERUS_MCP_PATH>` | the same document at the path-suffixed location some clients build |
| `/.well-known/oauth-authorization-server` | RFC 8414 document naming `/authorize`, `/token`, `S256`, the two grants, `token_endpoint_auth_methods_supported: ["none"]`, and `offline_access` among its scopes |
| `/authorize` | starts the flow; requires a registered `redirect_uri` and an S256 PKCE challenge |
| `/authorize/callback` | Google's callback, registered in Google Cloud |
| `/token` | `grant_type=authorization_code` and `grant_type=refresh_token` |

A `401` from the MCP endpoint that is a statement about the credential carries
`WWW-Authenticate: Bearer realm="cerberus-db-mcp", resource_metadata="<CERBERUS_AUTH_PUBLIC_BASE_URL>/.well-known/oauth-protected-resource"`,
which is how a client that has only ever seen a refusal finds the rest.

### The flow, end to end

1. The client fetches the protected-resource document, follows it to the
   authorization-server document, and sends the operator's browser to
   `/authorize` with its own `redirect_uri`, `state` and S256 PKCE challenge.
2. This server asks Google for consent with `access_type=offline` and
   `prompt=consent`, using its own client secret and its own PKCE verifier. The
   client's challenge and redirect URI travel in a sealed `state` parameter, so
   nothing is stored here and a restart mid-flow breaks nothing.
3. Google returns to `/authorize/callback`. This server exchanges the code, asks
   Google's Tokeninfo who the caller is, checks that address against
   `CERBERUS_AUTH_ALLOWED_EMAILS`, and redirects the client back to its own
   `redirect_uri` with an authorization code of this server's — a sealed value
   carrying Google's refresh token, the identity, the client's PKCE challenge and
   a five-minute expiry.
4. The client posts that code, its `code_verifier` and its `redirect_uri` to
   `/token` and gets back `access_token`, `refresh_token`, `token_type: "Bearer"`
   and `expires_in: 3600`. Both values are sealed with
   `CERBERUS_AUTH_SEALING_SECRET` and are opaque to the client.
5. The client calls tools with the access credential as a bearer token for an
   hour, then posts `grant_type=refresh_token` to `/token` with no browser
   involved. Every renewal spends Google's refresh token against Google,
   re-derives the identity through Tokeninfo, and re-checks it against the
   allowlist before issuing anything.

No client secret is issued, stored or checked by this server: every client is
public, and the PKCE `code_verifier` is the whole of what authenticates the caller
at `/token`.

### Configuring Claude Code

```sh
claude mcp add --transport http cerberus-db https://<public-hostname>/mcp
```

Claude Code discovers the rest: the first call gets a `401` naming the
protected-resource document, and the browser sign-in follows from there. Before
that works, the redirect URI Claude Code uses has to be listed in
`CERBERUS_AUTH_CLIENT_REDIRECT_URIS` exactly as the client sends it — that list is
the whole client registry, matched by string equality, and there is no dynamic
registration to fill it in. The value the client sent appears in nothing this
server logs, so take it from the client's own configuration or from the
`redirect_uri` in the browser's address bar when `/authorize` refuses it with
`invalid redirect URI`.

Claude web and desktop custom connectors are configured with the same URL. Whether
they complete a flow against a non-Anthropic authorization server has not been
established here.

### What ends a session

- Revoking this server's grant in Google Account permissions. The next renewal
  spends a refresh token Google no longer honours, `/token` answers `400
  {"error":"invalid_grant"}`, and the client starts again at a browser. The
  access credential already issued keeps working for the rest of its hour.
- Removing the address from `CERBERUS_AUTH_ALLOWED_EMAILS` and restarting. The
  next renewal is refused `403`.
- Changing `CERBERUS_AUTH_SEALING_SECRET`. Every credential this server ever
  issued stops opening at once, for everybody.

A restart ends nothing. This process stores no session — the credentials carry
everything they need — so a redeploy with the same sealing secret leaves every
connected client connected.

### Authorization codes are not replay-checked

This server is stateless on purpose: it stores nothing, and a restart invalidates
no session. That means it has nowhere to record that an authorization code has
already been spent, so a code presented twice at `/token` inside its five-minute
window is honoured twice. What bounds that is the five-minute expiry and the PKCE
binding: the code alone is useless, because whoever presents it must also produce
the verifier whose S256 hash the client sent to `/authorize`, and that verifier
never travels the path the code does — it is not in the redirect, not in the
browser's history, and not sent to Google. Closing the gap properly would mean
giving this process a store to remember spent codes in, which is the trade this
design refused.

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

The compose file also bind-mounts the `gate` directory beside it, read-only, at
`/etc/cerberus-db-mcp/gate`. It mounts the directory rather than one file so
that an editor that replaces the file on save still leaves the container seeing
the new one. The compose file does not set `CERBERUS_MCP_GATE_OVERLAY`; without
it in `.env`, the service runs the baseline exactly as it would with no mount.
Create the directory yourself rather than letting Docker create it as `root`:
the image runs as uid `65532`, so the directory has to be traversable and the
file readable by that user. To configure an overlay, from the stack directory:

```sh
mkdir -p gate && chmod 755 gate
$EDITOR gate/overlay.json
chmod 644 gate/overlay.json
echo 'CERBERUS_MCP_GATE_OVERLAY=/etc/cerberus-db-mcp/gate/overlay.json' >> .env
docker compose up -d
```

Changing the variable takes `docker compose up -d`, which recreates the
container. Changing the file takes only a reload. The binary is the container's
PID 1, so the signal reaches it directly:

```sh
docker compose kill -s HUP cerberus-db-mcp
docker compose logs --since 1m cerberus-db-mcp | grep 'gate'
```

The log shows either the reload event with the new diff or the rejection with
its reason; "Gate overlay" above describes both.

The external SQL Server is reachable through a VPN that must be up on the Pi,
not on a laptop. Startup does not ping databases, so the service can start while
the VPN is down and only fail when the first query attempts to connect.

### Cloudflare Tunnel

`cloudflared` is operator-managed in its own container and is intentionally not
defined by this repository's compose file. It must join the same `homelab`
network and route the whole public hostname to the application container. The
hostname rule must not be narrowed to `/mcp`: the MCP endpoint is only one part
of the public surface, and a path rule for it alone leaves the authorization
flow unreachable at the edge.

```yaml
ingress:
  - hostname: <public-hostname>
    service: http://cerberus-db-mcp:8080
```

The port in this example must match the port the container actually listens on.
The tracked compose file and the deployment have been observed to disagree, so
use the [port-discovery step in the manual checks](.ai-kit/plans/a-claude-code-session-that-outlives-the-hour/manual-checks.md#criterion-2--confirm-that-the-public-surface-reaches-the-origin)
before relying on it. A correct path rule directed at the wrong port produces a
Cloudflare 502 over a healthy origin, which is indistinguishable from an
application fault unless the port is checked.

That one hostname rule has to carry all six tunnel-routed paths to the origin:
`/authorize`, `/authorize/callback`, and `/token`; the authorization-server
document at `/.well-known/oauth-authorization-server`; the protected-resource
documents at `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource<CERBERUS_MCP_PATH>`. `GET /healthz` is
deliberately outside the Cloudflare tunnel. The OAuth surface is reachable
through the public hostname only when the tunnel routes all six paths, not
merely the authenticated MCP path.

After a tunnel or application deploy, confirm the entire public surface from a
checkout:

```sh
go run ./tools/reachability https://cerberus-db-mcp.alanv.me
```

When `CERBERUS_MCP_PATH` is not `/mcp`, pass its value with `-mcp-path`; without
it, the tool probes `/mcp` and its suffixed protected-resource document, which
both return edge 404s and can look like a tunnel problem rather than a flag
problem.

It probes `/healthz` first. Because that path is deliberately outside the
tunnel, the tool exits 1 on an otherwise healthy deployment. It checks each
path without credentials and distinguishes a Cloudflare edge 404 from an
origin 404.

### Interpreting 403 responses

An allowlist refusal at the MCP endpoint returns `forbidden: this identity is not
allowed on this server` and writes an application log record with
`auth_refusal=identity_allowlist`. Add the verified address to
`CERBERUS_AUTH_ALLOWED_EMAILS` when that is the intended caller.

A renewal refused for the same reason is a different event: `POST /token` answers
`403` with `{"error":"access_denied"}` and the log record carries
`auth_refusal=renewal_identity_allowlist`. It means a client that was signed in
tried to renew and the address behind it is no longer on the allowlist, so the
session ends there. The two are deliberately distinguishable — the first is a
request that never reached a tool, the second is a session that has just been
closed.

The MCP SDK has a separate Host-header refusal, but it cannot occur in this
container topology because the service binds `0.0.0.0:8080`, not a loopback
address. If it does ever appear, its body is `Forbidden: invalid Host header
"..."` and the codebase writes no log line at all. That absence is the way to
tell it apart from an identity-allowlist refusal. The SDK rule remains relevant
when running the binary directly with its loopback default.

## Raspberry Pi deployment of cerberus-cache-mcp

The Redis MCP server ships as a second image, `ghcr.io/alanisaacv/cerberus-cache-mcp`,
built from the same Dockerfile (target `cerberus-cache-mcp`) and published by the
same release run, on the same version, as `ghcr.io/alanisaacv/cerberus-db-mcp`.
Its entrypoint is `/usr/local/bin/cerberus-cache-mcp`, and the image contains no
other binary. It runs as its own service, from its own stack directory, beside the
SQL stack; nothing in the SQL stack changes.

Like the SQL deployment, this has not yet been run on the Pi.

### The stack directory

On the Pi, create `/opt/stacks/cerberus-cache-mcp` and copy into it:

- `deploy/cache/compose.yaml` as `compose.yaml`;
- `deploy/cache/.env.example` as `.env`, then fill it in.

The compose file runs one service, `cerberus-cache-mcp`, from the `:latest`
image, restarts it unless stopped, sets `CERBERUS_MCP_ADDRESS=0.0.0.0:8080`, and
starts at `mem_reservation: 64m` and `mem_limit: 256m` — starting points, not
measurements; "Measure memory before tuning it" below applies with the service
name changed. It publishes no host port and joins the external `homelab`
network, which must already exist. It has no healthcheck, for the reason
"Health and logs" gives, and no gate mount: the Redis binary reads no overlay.
`.env` is required, so a stack directory without one fails at `docker compose`
rather than starting a restart loop.

Deploy and update from that directory with:

```sh
docker compose pull && docker compose up -d
```

To roll back, pin a release tag such as `:vX.Y.Z` in `image:` and repeat
`docker compose pull && docker compose up -d`. Both images carry the same
version, so the tag that matches a SQL release is the one built from the same
commit.

The first release that publishes this image creates a new ghcr package. If the
SQL package is public and the Pi pulls without logging in, give the new package
the same visibility in its package settings before the first pull.

### The env file

`deploy/cache/.env.example` names every variable the Redis binary reads and
nothing else. A blank value is the same as unset.

- `CERBERUS_MCP_*`: as in "Defaulted or optional" above. The compose file's
  `CERBERUS_MCP_ADDRESS` takes precedence over the one in `.env`, so the listen
  address is changed in `compose.yaml`, not in `.env`. There is no
  `CERBERUS_MCP_GATE_OVERLAY` here.
- `CERBERUS_AUTH_*`: the same six variables, with the same rules, as in
  "Required" above. The sections below cover the two whose values differ from
  the SQL server's: `CERBERUS_AUTH_PUBLIC_BASE_URL`, and the choice behind
  `CERBERUS_AUTH_SEALING_SECRET`. `CERBERUS_AUTH_CLIENT_REDIRECT_URIS` lists the
  redirect URIs of the clients that connect to this server.
- Redis settings, each shown at its default: `CERBERUS_REDIS_COMMAND_TIMEOUT`
  (`20s`), `CERBERUS_REDIS_CONNECT_TIMEOUT` (`10s`), `CERBERUS_REDIS_MAX_CONNS`
  (`4`, per `<alias>.<number>`), `CERBERUS_REDIS_REPLY_BYTE_BUDGET` (`32768`),
  `CERBERUS_REDIS_MAX_ELEMENTS` (`1000`), `CERBERUS_REDIS_MAX_COUNT` (`1000`),
  `CERBERUS_REDIS_MAX_ARGS` (`1024`) and `CERBERUS_REDIS_MAX_ARGV_BYTES`
  (`65536`). Each must be positive.
- `CERBERUS_REDIS_ALIASES`: the comma-separated Redis aliases. The template
  configures one, `cache`. Each alias needs a variable family named after it,
  upper-cased with hyphens changed to underscores — for `cache`,
  `CERBERUS_REDIS_CACHE_HOST`, `CERBERUS_REDIS_CACHE_PORT`,
  `CERBERUS_REDIS_CACHE_USER`, `CERBERUS_REDIS_CACHE_PASSWORD` and
  `CERBERUS_REDIS_CACHE_DATABASES`, all required, and the optional
  `CERBERUS_REDIS_CACHE_TLS`.
- `_DATABASES` is a comma-separated list of logical database numbers, and each
  becomes an alias of its own named `<alias>.<number>`: the template's `cache`
  with `0` is what `list_connections` reports as `cache.0`.
- `_TLS` is `disable` when unset; `require` verifies the server's certificate
  against the host name, and `require-insecure` encrypts without verifying it.
- `_PASSWORD` refuses whitespace rather than trimming it.

A set `CERBERUS_REDIS_*` variable that belongs to no configured alias — one left
behind when an alias was removed, or a misspelled suffix — refuses startup and
names the variable. Startup does not connect to Redis, so a wrong host or
password shows up at the first tool call, not at `docker compose up`.

### A hostname of its own

The Redis server needs its own public hostname, such as
`https://<cache-hostname>`, and cannot live under a path of the SQL one. Every
route of the authorization flow — `/authorize`, `/authorize/callback`, `/token`
and the `/.well-known/` documents listed in "What is served" — is mounted at the
origin's root, so two servers behind one hostname would claim the same paths.

Set `CERBERUS_AUTH_PUBLIC_BASE_URL` to that origin, with the same rules as
above, and register `<CERBERUS_AUTH_PUBLIC_BASE_URL>/authorize/callback` as an
authorized redirect URI on the Google OAuth client this server uses. That can be
the SQL server's client, with the new callback added beside the existing one, or
a client of its own; `CERBERUS_AUTH_GOOGLE_CLIENT_ID` and
`CERBERUS_AUTH_GOOGLE_CLIENT_SECRET` follow whichever you choose.

### Sharing the sealing secret, or not

`CERBERUS_AUTH_SEALING_SECRET` is the key every credential this server issues is
sealed with, and a credential carries no record of which server issued it.

- **Shared with the SQL server**: a credential issued by either server opens the
  other. Each server still applies its own `CERBERUS_AUTH_ALLOWED_EMAILS` to every
  request, so this matters only for identities both allowlists admit. Rotating
  the secret means changing it in both stacks, which signs everybody out of
  both.
- **Separate**: generate a new base64-encoded 32-byte value for this stack. Each
  server's credentials open only that server, each client signs in to each
  server separately, and either secret can be rotated without touching the other.

### The read-only ACL user on each Redis

The command gate in the binary is the first layer of read-only enforcement. The
second is the Redis account it connects as. On each Redis instance an alias
points at, create a user that can read and select a database, and nothing else —
the rule the integration tests run against:

```text
ACL SETUSER <user> on ><password> ~* &* +@read +select
```

Put that user and password in the alias's `_USER` and `_PASSWORD`. `ACL SETUSER`
takes effect immediately but lasts only until the instance restarts unless that
instance persists its ACLs (`ACL SAVE` with an ACL file, or `CONFIG REWRITE`).
The Pi has to reach each instance's host and port on its own network; nothing in
this repository can check that.

### Cloudflare Tunnel rule

Add a rule for the new hostname to the shared cloudflared configuration, routing
the whole hostname — not only `/mcp`, for the reason "Cloudflare Tunnel" above
gives — to the service by name over `homelab`:

```yaml
ingress:
  - hostname: <cache-hostname>
    service: http://cerberus-cache-mcp:8080
```

The port is the one in the compose file's `CERBERUS_MCP_ADDRESS`; change one
and the other has to follow. Then confirm the public surface the same way as
the SQL server's:

```sh
go run ./tools/reachability https://<cache-hostname>
```

### Connecting Claude Code

```sh
claude mcp add --transport http cerberus-cache https://<cache-hostname>/mcp
```

The sign-in works as described in "Configuring Claude Code", against this
server's own `CERBERUS_AUTH_CLIENT_REDIRECT_URIS` and allowlist. The `401`
challenge still names `realm="cerberus-db-mcp"`; that string is shared with the
SQL server's code and has no effect on the flow.

To see logs or memory, use the commands in "Health and logs" and "Measure memory
before tuning it" from `/opt/stacks/cerberus-cache-mcp`, with
`cerberus-cache-mcp` as the service name.

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

The application log also records which gate ruleset is in force: one event at
startup and one on every `SIGHUP`, each with its diff against the baseline, or
an error event when a reload was rejected. To see the latest:

```sh
docker compose logs cerberus-db-mcp | grep 'gate ruleset loaded\|gate overlay rejected'
```

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
