// Package gate decides, for exactly one SQL statement, whether that statement
// can be proven to be a read.
//
// The package is pure by design: no database driver, no MCP SDK, no network and
// no clock. Its only I/O is reading the optional ruleset file it is handed at
// construction. A verdict is a function of the statement, the engine, the grants
// passed in and the ruleset in force, and of nothing else.
//
// The gate is an allowlist. Only a statement whose leading keyword is on the
// read allowlist, that contains no forbidden keyword or forbidden construct,
// that is a single statement, and whose every function call names a function on
// the safe-builtin allowlist can reach [Allow]. Everything else is refused:
// known-dangerous constructs terminally as [Deny], and the merely unrecognised
// as [NeedsApproval], which a rule-scoped [Grant] can unblock.
//
// On SQL Server this gate is the only enforcement layer that will ever exist:
// T-SQL has no read-only transaction primitive. Every ambiguity therefore
// resolves to a refusal.
package gate

import "errors"

// Engine names a SQL dialect. It selects the lexical rules the tokenizer
// applies and scopes rules that hold for one dialect only.
type Engine string

const (
	MySQL      Engine = "mysql"
	PostgreSQL Engine = "postgresql"
	SQLServer  Engine = "sqlserver"
)

// ErrUnknownEngine identifies an engine name this package has no lexical rules
// for. There is no default dialect: guessing one would mean tokenizing a
// statement by rules the server does not use.
var ErrUnknownEngine = errors.New("unknown engine")

// Engines returns the supported engines in a stable order.
func Engines() []Engine {
	return []Engine{MySQL, PostgreSQL, SQLServer}
}

// ParseEngine converts an engine name from configuration or a corpus file.
func ParseEngine(s string) (Engine, error) {
	for _, e := range Engines() {
		if string(e) == s {
			return e, nil
		}
	}
	return "", ErrUnknownEngine
}

// Valid reports whether e is an engine this package can tokenize for.
func (e Engine) Valid() bool {
	_, ok := dialects[e]
	return ok
}

// dialect is the per-engine lexical specification. Every field corresponds to a
// documented divergence between the three engines; see the doc comments on each
// group and lexer.go for the rules they drive.
type dialect struct {
	// nestedBlockComments holds for T-SQL and PostgreSQL, and not for MySQL.
	// Microsoft: "If the /* character pattern occurs anywhere within an existing
	// comment, it is treated as the start of a nested comment and, therefore,
	// requires a closing */ comment mark."
	// https://learn.microsoft.com/en-us/sql/t-sql/language-elements/slash-star-comment-transact-sql
	// PostgreSQL, section 4.1.5: "These block comments nest, as specified in the
	// SQL standard but unlike C, so that one can comment out larger blocks of
	// code that might contain existing block comments."
	// https://www.postgresql.org/docs/current/sql-syntax-lexical.html
	//
	// Getting this wrong in either direction is a fail-open, not merely an
	// over-refusal. Ending a nested comment early leaves the tokenizer standing
	// on text the server is still treating as comment — and if that text opens a
	// line comment, everything the server does execute after the real */ is
	// hidden from the gate. See the corpus entries naming this defect.
	nestedBlockComments bool

	// executableComments is MySQL only: "MySQL Server parses and executes the
	// code within the comment as it would any other SQL statement."
	// /*! ... */ and /*!50000 ... */ are code, not comments.
	// https://dev.mysql.com/doc/refman/8.0/en/comments.html
	executableComments bool

	// lineCommentNeedsSpace is MySQL only: -- is a comment introducer only when
	// followed by whitespace or a control character, so "--DROP" is not a
	// comment there while it is in PostgreSQL and T-SQL.
	lineCommentNeedsSpace bool

	// hashLineComments is MySQL only. In T-SQL # introduces a temporary table
	// name instead; in PostgreSQL it is an operator character.
	hashLineComments bool

	// backslashEscapes is MySQL only, by default. PostgreSQL's plain '...' does
	// not process backslash escapes when standard_conforming_strings is on (the
	// default since 9.1) and T-SQL never treats backslash as a string escape.
	backslashEscapes bool

	// doubleQuoteIsString is MySQL only, by default. In PostgreSQL and T-SQL
	// "..." delimits an identifier. Under T-SQL's QUOTED_IDENTIFIER OFF it is a
	// string instead, but the two readings agree on where the token ends, and
	// neither reading makes the contents executable.
	doubleQuoteIsString bool

	backtickIdentifiers bool // MySQL `ident`
	bracketIdentifiers  bool // T-SQL [ident]]ifier]
	hashIdentifiers     bool // T-SQL #temp and ##global

	// dollarQuoting is PostgreSQL only: $$ ... $$ and $tag$ ... $tag$ take their
	// contents completely literally. A tag cannot begin with a digit, which is
	// what separates an opener from a $1 positional parameter.
	// https://www.postgresql.org/docs/current/sql-syntax-lexical.html
	dollarQuoting bool

	escapeStringPrefix bool // PostgreSQL E'...' always processes backslashes
	unicodePrefix      bool // PostgreSQL U&'...' and U&"..."
	nationalPrefix     bool // T-SQL and MySQL N'...'
	binaryPrefix       bool // MySQL and PostgreSQL X'ff' and B'01'; T-SQL writes 0xff
	atSignVariables    bool // MySQL @var/@@global, T-SQL @var/@@version
}

var dialects = map[Engine]dialect{
	MySQL: {
		executableComments:    true,
		lineCommentNeedsSpace: true,
		hashLineComments:      true,
		backslashEscapes:      true,
		doubleQuoteIsString:   true,
		backtickIdentifiers:   true,
		nationalPrefix:        true,
		binaryPrefix:          true,
		atSignVariables:       true,
	},
	PostgreSQL: {
		nestedBlockComments: true,
		dollarQuoting:       true,
		escapeStringPrefix:  true,
		unicodePrefix:       true,
		binaryPrefix:        true,
	},
	SQLServer: {
		nestedBlockComments: true,
		bracketIdentifiers:  true,
		hashIdentifiers:     true,
		nationalPrefix:      true,
		atSignVariables:     true,
	},
}
