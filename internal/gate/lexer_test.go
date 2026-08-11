package gate

import (
	"errors"
	"strings"
	"testing"
)

// words returns the unquoted word tokens, which is what every rule lookup and
// every boundary decision is made of. A lexical bug shows up here as a keyword
// that appears when it should not, or disappears when it should not.
func words(toks []token) []string {
	var out []string
	for _, t := range toks {
		if t.kind == tokenWord {
			out = append(out, t.lower)
		}
	}
	return out
}

func TestTokenizeDialectRules(t *testing.T) {
	for _, tt := range []struct {
		name   string
		engine Engine
		src    string
		want   []string
	}{
		{"mysql executable comment is code", MySQL, "SELECT 1 /*!DROP TABLE t*/", []string{"select", "drop", "table", "t"}},
		{"mysql versioned executable comment is code", MySQL, "/*!50000 DELETE FROM t */ SELECT 1", []string{"delete", "from", "t", "select"}},
		{"mysql executable comment without a space after the version", MySQL, "/*!50000SELECT*/ 1", []string{"select"}},
		{"executable comment is a comment elsewhere", PostgreSQL, "SELECT 1 /*!DROP TABLE t*/", []string{"select"}},
		{"mysql line comment needs whitespace", MySQL, "SELECT 1 --DROP TABLE t", []string{"select", "drop", "table", "t"}},
		{"mysql line comment with whitespace", MySQL, "SELECT 1 -- DROP TABLE t", []string{"select"}},
		{"postgresql line comment needs no whitespace", PostgreSQL, "SELECT 1 --DROP TABLE t", []string{"select"}},
		{"sqlserver line comment needs no whitespace", SQLServer, "SELECT 1 --DROP TABLE t", []string{"select"}},
		{"mysql hash comment", MySQL, "SELECT 1 # DROP TABLE t", []string{"select"}},
		{"postgresql has no hash comment", PostgreSQL, "SELECT 1 # DROP TABLE t", []string{"select", "drop", "table", "t"}},
		{"sqlserver block comments nest", SQLServer, "SELECT 1 /* /* */ DROP TABLE t */", []string{"select"}},
		{"postgresql block comments nest", PostgreSQL, "SELECT 1 /* /* */ DROP TABLE t */", []string{"select"}},
		{"mysql block comments do not nest", MySQL, "SELECT 1 /* /* */ DROP TABLE t */", []string{"select", "drop", "table", "t"}},
		// Ending a nested comment early does not merely reveal extra text — it can
		// hide text, when what follows the misplaced end is a line-comment
		// introducer the server is still treating as comment.
		{"postgresql nested comment does not hide the tail", PostgreSQL, "SELECT 1 /* /* */ -- */ , f()", []string{"select", "f"}},
		{"mysql non-nesting is the server's own reading", MySQL, "SELECT 1 /* /* */ -- */ , f()", []string{"select"}},
		{"postgresql nested comment with a hash tail", PostgreSQL, "SELECT 1 /* /* */ # */ , f()", []string{"select", "f"}},
		{"sqlserver bracket identifier escapes the closing bracket", SQLServer, "SELECT * FROM [t]]; DROP TABLE u--]", []string{"select", "from"}},
		{"sqlserver national literal", SQLServer, "SELECT N'DROP TABLE t'", []string{"select"}},
		{"mysql national literal", MySQL, "SELECT N'DROP TABLE t'", []string{"select"}},
		{"postgresql dollar quote", PostgreSQL, "SELECT $$; DROP TABLE t$$", []string{"select"}},
		{"postgresql tagged dollar quote", PostgreSQL, "SELECT $tag$; DROP TABLE t$tag$", []string{"select"}},
		{"postgresql positional parameter is not a dollar quote", PostgreSQL, "SELECT $1 ; DROP", []string{"select", "drop"}},
		{"postgresql escape string consumes the backslash", PostgreSQL, `SELECT E'\'; DROP TABLE t; --'`, []string{"select"}},
		{"postgresql plain string does not", PostgreSQL, `SELECT '\'; DROP TABLE t; --'`, []string{"select", "drop", "table", "t"}},
		{"mysql plain string does", MySQL, `SELECT '\'; DROP TABLE t; --'`, []string{"select"}},
		{"doubled quote in mysql", MySQL, "SELECT 'a''; DROP TABLE t'", []string{"select"}},
		{"doubled quote in postgresql", PostgreSQL, "SELECT 'a''; DROP TABLE t'", []string{"select"}},
		{"doubled quote in sqlserver", SQLServer, "SELECT 'a''; DROP TABLE t'", []string{"select"}},
		{"mysql double quotes delimit a string", MySQL, `SELECT "a""; DROP TABLE t"`, []string{"select"}},
		{"postgresql double quotes delimit an identifier", PostgreSQL, `SELECT "a""b" FROM t`, []string{"select", "from", "t"}},
		{"postgresql unicode string", PostgreSQL, `SELECT U&'d\0061t; DROP' AS x`, []string{"select", "as", "x"}},
		{"mysql backquoted identifier is never a keyword", MySQL, "SELECT `drop` FROM t", []string{"select", "from", "t"}},
		{"mysql binary literal prefix", MySQL, "SELECT X'44524f50'", []string{"select"}},
		{"postgresql binary literal prefix", PostgreSQL, "SELECT B'0101'", []string{"select"}},
		{"sqlserver has no binary literal prefix", SQLServer, "SELECT X'44524f50'", []string{"select", "x"}},
		{"sqlserver temporary table name", SQLServer, "SELECT * FROM #tmp", []string{"select", "from", "#tmp"}},
		{"variables are not words", SQLServer, "SELECT @@VERSION, @x", []string{"select"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			toks, err := tokenize(tt.engine, tt.src)
			if err != nil {
				t.Fatalf("tokenize(%s, %q) = %v", tt.engine, tt.src, err)
			}
			got := words(toks)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Fatalf("words = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizeErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		engine Engine
		src    string
		want   error
	}{
		{"unterminated string", MySQL, "SELECT 'abc", errUnterminatedString},
		{"unterminated national string", SQLServer, "SELECT N'abc", errUnterminatedString},
		{"unterminated dollar quote", PostgreSQL, "SELECT $tag$abc", errUnterminatedString},
		{"unterminated block comment", PostgreSQL, "SELECT 1 /* abc", errUnterminatedComment},
		{"unterminated nested block comment", SQLServer, "SELECT 1 /* /* */", errUnterminatedComment},
		{"unterminated executable comment", MySQL, "SELECT /*!50000 1", errUnterminatedComment},
		{"unterminated bracket identifier", SQLServer, "SELECT * FROM [t", errUnterminatedIdentifier},
		{"unterminated backquoted identifier", MySQL, "SELECT `t", errUnterminatedIdentifier},
		{"backslash outside a literal", MySQL, `SELECT 1 \G`, errUnsupportedCharacter},
		{"backquote outside mysql", PostgreSQL, "SELECT `t`", errUnsupportedCharacter},
		{"unknown engine", Engine("oracle"), "SELECT 1", ErrUnknownEngine},
	} {
		t.Run(tt.name, func(t *testing.T) {
			toks, err := tokenize(tt.engine, tt.src)
			if err == nil {
				t.Fatalf("tokenize(%s, %q) = %v, want %v", tt.engine, tt.src, words(toks), tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("tokenize(%s, %q) = %v, want %v", tt.engine, tt.src, err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "gate: ") {
				t.Fatalf("error %q does not carry the package prefix", err)
			}
		})
	}
}

func TestTokenizeTerminates(t *testing.T) {
	// Every branch of the lexer must consume at least one byte. These inputs are
	// the ones where a missing advance would spin forever rather than fail.
	for _, tt := range []struct {
		engine Engine
		src    string
	}{
		{PostgreSQL, "$"},
		{PostgreSQL, "$$$$"},
		{PostgreSQL, "$ $"},
		{PostgreSQL, "$1$1"},
		{MySQL, "--"},
		{MySQL, "-"},
		{MySQL, "#"},
		{MySQL, "/*!"},
		{MySQL, "/*!*/"},
		{MySQL, "*/"},
		{SQLServer, "/**/"},
		{SQLServer, "[]"},
		{SQLServer, "@"},
		{SQLServer, "@@"},
		{MySQL, "0x"},
		{MySQL, "1e"},
		{MySQL, "1."},
		{PostgreSQL, "''"},
	} {
		t.Run(string(tt.engine)+"/"+tt.src, func(t *testing.T) {
			_, _ = tokenize(tt.engine, tt.src)
		})
	}
}
