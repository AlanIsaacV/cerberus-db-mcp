package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

// secretiveSpec is an alias every one of whose values is a distinctive string,
// so that finding one in an agent-facing message is unambiguous evidence.
func secretiveSpec() AliasSpec {
	return AliasSpec{
		Alias:    "warehouse",
		Engine:   gate.SQLServer,
		Host:     "sql-01.corp.internal.example",
		Port:     14330,
		Database: "OperationsWarehouse",
		User:     "svc_cerberus_reader",
		Password: Secret("Tr0ub4dor&3-actual-password"),
	}
}

// TestEveryKindHasASentinelAndAMessage is the check that keeps the allowlist an
// allowlist. A Kind with no message would fall through to the internal message,
// which is safe; a Kind with no sentinel would be unmatchable with errors.Is,
// which is not. Both are caught here rather than in review.
//
// The kinds are read out of the source rather than listed here. A hand-written
// list only ever catches a sentinel or a message added out of step with the list
// itself: adding a Kind constant and forgetting both leaves every count equal and
// the test green, which is the one case that matters. Parsing the declarations is
// the same technique deps_test.go uses, and it means the thing under test is the
// package's own const block.
func TestEveryKindHasASentinelAndAMessage(t *testing.T) {
	kinds := declaredKinds(t)
	if len(kinds) < 2 {
		t.Fatalf("found %d Kind constants in the source, which means the parse found nothing rather than that the package has none", len(kinds))
	}
	if len(kinds) != len(kindSentinels) {
		t.Errorf("the source declares %d kinds and there are %d sentinels", len(kinds), len(kindSentinels))
	}
	if len(kinds) != len(agentMessages) {
		t.Errorf("the source declares %d kinds and there are %d agent messages", len(kinds), len(agentMessages))
	}
	seen := map[error]Kind{}
	for name, k := range kinds {
		sentinel, ok := kindSentinels[k]
		if !ok {
			t.Errorf("%s (%q) has no sentinel, so no caller can match it with errors.Is", name, k)
			continue
		}
		if other, dup := seen[sentinel]; dup {
			t.Errorf("kinds %q and %q share one sentinel, so errors.Is cannot tell them apart", other, k)
		}
		seen[sentinel] = k
		if strings.TrimSpace(agentMessages[k]) == "" {
			t.Errorf("%s (%q) has no agent-facing message", name, k)
		}
	}
}

func TestPermissionDeniedDoesNotClaimAnythingAboutAccountPrivileges(t *testing.T) {
	message := (&Error{Kind: KindPermissionDenied}).Agent()
	for _, forbidden := range []string{"read-only account", "account privileges", "account is read-only"} {
		if strings.Contains(message, forbidden) {
			t.Errorf("permission-denied message makes an unsupported privilege claim %q: %s", forbidden, message)
		}
	}
}

// declaredKinds returns every constant of type Kind declared in this package's
// non-test files, keyed by the constant's Go name so a failure can name it.
//
// A Kind declared without a string literal is reported rather than skipped: this
// package's guarantee is that the value an [Error] carries is one of an enumerated
// set, and a Kind whose value this test cannot read is a Kind it cannot check.
//
// A constant in a Kind block counts whether or not it carries an explicit type,
// and that is not pedantry. `KindUntyped = "untyped"` in the same block is an
// untyped string constant, which Go assigns to a Kind field without a conversion,
// so Error{Kind: KindUntyped} compiles and reaches [Error.Agent] — a Kind with no
// sentinel, which is the exact hole this test exists to close. Requiring vs.Type
// to say "Kind" would skip it and leave the test green.
func declaredKinds(t *testing.T) map[string]Kind {
	t.Helper()
	out := map[string]Kind{}
	fset := gotoken.NewFileSet()
	for _, file := range nonTestFiles(t) {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != gotoken.CONST || !declaresAKind(gen) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				// Nothing to skip for an absent type — see above. A type that is
				// present and is not Kind is a constant of some other type sharing the
				// block, which is not assignable to a Kind field.
				if vs.Type != nil && !isKindIdent(vs.Type) {
					continue
				}
				for i, name := range vs.Names {
					where := fmt.Sprintf("%s:%d", file, fset.Position(name.Pos()).Line)
					if i >= len(vs.Values) {
						t.Errorf("%s: %s is a Kind with no value", where, name.Name)
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != gotoken.STRING {
						t.Errorf("%s: %s is a Kind whose value is not a string literal, so this test cannot check it", where, name.Name)
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Errorf("%s: %s has an unreadable value: %v", where, name.Name, err)
						continue
					}
					out[name.Name] = Kind(value)
				}
			}
		}
	}
	return out
}

// declaresAKind reports whether a const block declares at least one constant
// explicitly typed Kind. It is what scopes the untyped-constant rule to the Kind
// block: the package has other const blocks whose members are untyped strings —
// the per-alias variable suffixes, for one — and those are not Kinds.
func declaresAKind(gen *ast.GenDecl) bool {
	for _, spec := range gen.Specs {
		if vs, ok := spec.(*ast.ValueSpec); ok && vs.Type != nil && isKindIdent(vs.Type) {
			return true
		}
	}
	return false
}

func isKindIdent(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && ident.Name == "Kind"
}

// TestAgentFacingMessagesCarryNoConfiguredValue is acceptance criterion 8's unit
// half: whatever an engine says, the agent's side of the error is built from the
// allowlist. The engine errors here are constructed to be as hostile as a real
// one can be — each carries every value the alias was configured with.
func TestAgentFacingMessagesCarryNoConfiguredValue(t *testing.T) {
	spec := secretiveSpec()
	everything := fmt.Sprintf("connection to %s:%d database %s as user %s password %s failed",
		spec.Host, spec.Port, spec.Database, spec.User, spec.Password.reveal())

	for _, tt := range []struct {
		name string
		err  error
		want Kind
	}{
		{
			name: "a postgres error mentioning everything",
			err:  &pgconn.PgError{Code: "28P01", Message: everything},
			want: KindUnavailable,
		},
		{
			name: "a mysql error mentioning everything",
			err:  &mysqldriver.MySQLError{Number: 1045, Message: everything},
			want: KindUnavailable,
		},
		{
			name: "a sql server error mentioning everything, including its own ServerName",
			err:  mssql.Error{Number: 18456, Message: everything, ServerName: spec.Host},
			want: KindUnavailable,
		},
		{
			name: "a dial failure, which carries the address by construction",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")},
			want: KindUnavailable,
		},
		{
			name: "a syntax error, where withholding the text costs the agent something and is done anyway",
			err:  &pgconn.PgError{Code: "42601", Message: `syntax error at or near "SELCT"`},
			want: KindInvalidStatement,
		},
		{
			name: "a permission denial on a real object",
			err:  mssql.Error{Number: 229, Message: "The SELECT permission was denied on the object 'Invoices'"},
			want: KindPermissionDenied,
		},
		{
			name: "a statement timeout",
			err:  &pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"},
			want: KindTimeout,
		},
		{
			name: "a lock timeout",
			err:  mssql.Error{Number: 1222, Message: "Lock request time out period exceeded"},
			want: KindLockTimeout,
		},
		{
			name: "a write refused by a read-only transaction",
			err:  &mysqldriver.MySQLError{Number: 1792, Message: "Cannot execute statement in a READ ONLY transaction"},
			want: KindReadOnlyTransaction,
		},
		{
			name: "something no engine has emitted yet",
			err:  errors.New("something entirely new happened at " + everything),
			want: KindInternal,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbErr := executionError(context.Background(), "execute", spec, tt.err)
			if dbErr.Kind != tt.want {
				t.Errorf("Kind = %q, want %q", dbErr.Kind, tt.want)
			}
			assertAgentSideIsClean(t, dbErr, spec)

			// The other half of the criterion: the operator's side must still
			// carry the detail, so the test tells sanitising apart from
			// discarding.
			if dbErr.Detail == "" {
				t.Error("the operator-facing detail is empty, so the error was discarded rather than sanitised")
			}
			if !strings.Contains(dbErr.Error(), dbErr.Detail) {
				t.Error("Error() does not include the detail an operator needs")
			}
			// The password is the one thing removed from the operator's side too.
			if strings.Contains(dbErr.Error(), spec.Password.reveal()) {
				t.Error("the password survived into the operator-facing text")
			}
		})
	}
}

func assertAgentSideIsClean(t *testing.T, dbErr *Error, spec AliasSpec) {
	t.Helper()
	agent := dbErr.Agent()
	for _, forbidden := range []struct {
		what  string
		value string
	}{
		{"host", spec.Host},
		{"port", fmt.Sprint(spec.Port)},
		{"database", spec.Database},
		{"user", spec.User},
		{"password", spec.Password.reveal()},
	} {
		if strings.Contains(agent, forbidden.value) {
			t.Errorf("the agent-facing message carries the %s: %s", forbidden.what, agent)
		}
	}
	if strings.TrimSpace(agent) == "" {
		t.Error("the agent-facing message is empty, which tells the agent nothing at all")
	}
}

// TestRefusalAgentMessageCarriesTheGatesOwnWords pins the one exception to the
// allowlist and the reason it is safe.
func TestRefusalAgentMessageCarriesTheGatesOwnWords(t *testing.T) {
	spec := secretiveSpec()
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	decision := g.Validate(spec.Engine, "DROP TABLE dbo.Invoices", nil)
	dbErr := refusalError("execute", spec, decision)

	agent := dbErr.Agent()
	if !strings.Contains(agent, string(decision.Reason)) {
		t.Errorf("the agent is not told the gate's reason: %s", agent)
	}
	if decision.RuleID != "" && !strings.Contains(agent, decision.RuleID) {
		t.Errorf("the agent is not told which rule refused it: %s", agent)
	}
	assertAgentSideIsClean(t, dbErr, spec)

	if !errors.Is(dbErr, ErrRefused) {
		t.Errorf("a refusal does not match ErrRefused")
	}
	// The decision on the error is a copy, so a caller cannot reach into the
	// gate's own value through it.
	dbErr.Decision.Reason = "tampered"
	if decision.Reason == "tampered" {
		t.Error("the error shares the caller's decision value")
	}
}

func TestClassifyLeansOnTheContextForItsOwnDeadline(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()

	for _, tt := range []struct {
		name string
		ctx  context.Context
		err  error
		want Kind
	}{
		{"the context's own error", context.Background(), context.DeadlineExceeded, KindTimeout},
		{"a cancelled caller", context.Background(), context.Canceled, KindCancelled},
		{
			// A driver can report an expired deadline as a cancellation, which is
			// not the same thing to a caller. The context is the tiebreaker.
			name: "a cancellation raised by our own expired deadline",
			ctx:  expired,
			err:  context.Canceled,
			want: KindTimeout,
		},
		{
			name: "a torn-down connection under an expired deadline",
			ctx:  expired,
			err:  fmt.Errorf("write tcp: %w", net.ErrClosed),
			want: KindTimeout,
		},
		{
			name: "the same torn-down connection with no deadline in play",
			ctx:  context.Background(),
			err:  fmt.Errorf("write tcp: %w", net.ErrClosed),
			want: KindUnavailable,
		},
		{"a bad pooled connection", context.Background(), driver.ErrBadConn, KindUnavailable},
		{"a finished transaction", context.Background(), sql.ErrConnDone, KindUnavailable},
		{
			// A gate-approved statement that produced no result set is a defect in
			// this process, not a fact about the network. Classifying it as
			// unavailable would tell the agent the database is unreachable and put
			// database-unavailable in the operator's log for a database that
			// answered.
			name: "a statement that returned nothing to read",
			ctx:  context.Background(),
			err:  errNoResultSet,
			want: KindInternal,
		},
		{
			// The same sentinel under an expired deadline is a timeout, because the
			// caller did time out: a statement stopped at the bound can surface as
			// an empty cursor rather than as an error the driver names. Classifying
			// it from the sentinel instead would tell an agent that waited out its
			// whole limit that the call failed for an unknown reason, and would put
			// "internal" in the operator's log for a plain timeout.
			name: "a statement that returned nothing to read as the deadline expired",
			ctx:  expired,
			err:  errNoResultSet,
			want: KindTimeout,
		},
		{
			// An expired deadline outranks the engine's own code, deliberately. The
			// cost is visible here rather than hidden: an engine error that arrives
			// in the same instant the bound expires is reported as a timeout, and
			// what it actually said survives in Detail. The benefit is that no
			// spelling of "stopped at the bound" has to be enumerated to be
			// classified.
			//
			// The read-only violation is the one exception, and it is not subject to
			// this trade — see
			// TestAReadOnlyViolationSurvivesAnExpiredDeadline.
			name: "an engine error arriving as the deadline expired",
			ctx:  expired,
			err:  &pgconn.PgError{Code: "42501", Message: "permission denied for table invoices"},
			want: KindTimeout,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.ctx, tt.err); got != tt.want {
				t.Errorf("classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAReadOnlyViolationSurvivesAnExpiredDeadline is the exception to the
// context-first rule above, and the reason it is worth an exception. A read-only
// violation means a write reached the engine, which means something got past the
// gate — the one class this package describes as an alarm an operator should
// treat as one. A slow write that trips the deadline on its way to being refused
// would otherwise be filed as an ordinary timeout, and the alarm would be lost
// in exactly the case where it is loudest.
//
// The negative half is the control: an error that is not one of these two codes
// is still a timeout under the same context, so this test proves the exception is
// narrow rather than that the ordering was inverted wholesale.
func TestAReadOnlyViolationSurvivesAnExpiredDeadline(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()

	for _, tt := range []struct {
		name string
		err  error
		want Kind
	}{
		{
			name: "postgres refusing a write with SQLSTATE 25006",
			err:  &pgconn.PgError{Code: "25006", Message: "cannot execute INSERT in a read-only transaction"},
			want: KindReadOnlyTransaction,
		},
		{
			name: "postgres SQLSTATE 25006 wrapped by a driver",
			err:  fmt.Errorf("exec: %w", &pgconn.PgError{Code: "25006", Message: "cannot execute UPDATE in a read-only transaction"}),
			want: KindReadOnlyTransaction,
		},
		{
			name: "mysql refusing a write with error 1792",
			err:  &mysqldriver.MySQLError{Number: 1792, Message: "Cannot execute statement in a READ ONLY transaction"},
			want: KindReadOnlyTransaction,
		},
		{
			name: "a neighbouring postgres code is still a timeout under the same context",
			err:  &pgconn.PgError{Code: "25001", Message: "active sql transaction"},
			want: KindTimeout,
		},
		{
			name: "a neighbouring mysql number is still a timeout under the same context",
			err:  &mysqldriver.MySQLError{Number: 1791, Message: "something else entirely"},
			want: KindTimeout,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(expired, tt.err); got != tt.want {
				t.Errorf("classify() = %q, want %q", got, tt.want)
			}
			// And the agent still learns nothing it should not, which is the
			// property the reordering must not have cost.
			spec := secretiveSpec()
			assertAgentSideIsClean(t, executionError(expired, "execute", spec, tt.err), spec)
		})
	}
}

func TestScrubRemovesThePasswordAndNothingElse(t *testing.T) {
	spec := secretiveSpec()
	in := fmt.Sprintf("sqlserver://%s:%s@%s?database=%s", spec.User, spec.Password.reveal(), spec.Host, spec.Database)
	got := scrub(spec, in)
	if strings.Contains(got, spec.Password.reveal()) {
		t.Fatalf("the password survived: %s", got)
	}
	for _, keep := range []string{spec.User, spec.Host, spec.Database} {
		if !strings.Contains(got, keep) {
			t.Errorf("scrub removed %q, which an operator needs", keep)
		}
	}
	if !strings.Contains(got, redacted) {
		t.Errorf("scrub did not mark where the password was: %s", got)
	}
}
