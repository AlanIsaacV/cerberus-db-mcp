# cerberus-db-mcp

cerberus-db-mcp is a gated, read-only Model Context Protocol server for MySQL,
PostgreSQL, and SQL Server. An authenticated Google identity must be on the
deployment's allowlist before it can reach a tool; the statement gate executes
no statement it cannot establish is a read, and each query is audited with the
calling identity.

## Configuration

Copy the root `.env.example` to an untracked `.env` and fill in the required
values. Configuration is environment-only: no configuration file is read by the
process, and the `.env` file must not be committed. The deployment compose file
loads an `.env` beside it.

### Required

- `CERBERUS_DB_ALIASES`: comma-separated database aliases. Each alias must have
  the following six variables, replacing `<ALIAS>` with the alias upper-cased
  and with hyphens changed to underscores:
  `CERBERUS_DB_<ALIAS>_ENGINE` (`mysql`, `postgresql`, or `sqlserver`),
  `CERBERUS_DB_<ALIAS>_HOST`, `CERBERUS_DB_<ALIAS>_PORT`,
  `CERBERUS_DB_<ALIAS>_DATABASE`, `CERBERUS_DB_<ALIAS>_USER`, and
  `CERBERUS_DB_<ALIAS>_PASSWORD`.
- `CERBERUS_AUTH_GOOGLE_CLIENT_ID`: the Google OAuth client ID that issued the
  access tokens this deployment accepts.
- `CERBERUS_AUTH_ALLOWED_EMAILS`: the comma-separated verified Google email
  addresses allowed to reach a tool.

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

SQL Server has no container coverage because no arm64 image is available. That
engine is exercised only against a real instance; it has not been verified
against the third-party SQL Server deployment target.
