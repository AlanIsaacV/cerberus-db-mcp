package gate

import (
	"errors"
	"fmt"
	"strings"
)

type tokenKind uint8

const (
	tokenWord        tokenKind = iota // unquoted identifier or keyword
	tokenQuotedIdent                  // "ident", `ident`, [ident]
	tokenString                       // 'lit', N'lit', E'lit', $$lit$$, X'ff'
	tokenNumber
	tokenPunct    // one character of punctuation or operator
	tokenVariable // @var, @@var, $1, ?
)

// token carries the lowercased text separately because every rule lookup is
// case-insensitive while error details quote the text as the caller wrote it.
// For a quoted identifier, text is the content with its delimiters removed and
// its doubled delimiters collapsed, so that a rule matching a function name
// matches whether or not the caller quoted the call.
type token struct {
	kind  tokenKind
	text  string
	lower string
	pos   int
}

var (
	errUnterminatedString     = errors.New("unterminated string literal")
	errUnterminatedIdentifier = errors.New("unterminated quoted identifier")
	errUnterminatedComment    = errors.New("unterminated block comment")
	errUnsupportedCharacter   = errors.New("unsupported character")
)

// tokenize splits src into tokens under engine's lexical rules. Comments are
// dropped, except MySQL's /*! ... */ whose contents are tokenized in band
// because the server executes them.
//
// Any failure is a refusal, not a best effort: a tokenizer that guesses where a
// string ends is a tokenizer that can hide a keyword.
func tokenize(engine Engine, src string) ([]token, error) {
	d, ok := dialects[engine]
	if !ok {
		return nil, fmt.Errorf("gate: tokenize statement: %w", ErrUnknownEngine)
	}
	l := lexer{d: d, src: src}
	if err := l.run(); err != nil {
		return nil, fmt.Errorf("gate: tokenize %s statement: %w", engine, err)
	}
	return l.toks, nil
}

type lexer struct {
	d    dialect
	src  string
	i    int
	toks []token

	// execDepth counts open MySQL executable comments. Their contents are live
	// code, so the lexer stays in normal mode inside them and only has to
	// recognise the closing */ that would otherwise tokenize as two operators.
	execDepth int
}

func (l *lexer) run() error {
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case isSpace(c):
			l.i++

		case l.execDepth > 0 && c == '*' && l.peek(1) == '/':
			l.execDepth--
			l.i += 2

		case c == '-' && l.peek(1) == '-' && l.lineCommentStarts():
			l.skipLineComment(l.i + 2)

		case l.d.hashLineComments && c == '#':
			l.skipLineComment(l.i + 1)

		case c == '/' && l.peek(1) == '*':
			if err := l.blockComment(); err != nil {
				return err
			}

		case c == '\'':
			if err := l.quoted(tokenString, '\'', l.d.backslashEscapes); err != nil {
				return err
			}

		case c == '"':
			if l.d.doubleQuoteIsString {
				if err := l.quoted(tokenString, '"', l.d.backslashEscapes); err != nil {
					return err
				}
			} else if err := l.quoted(tokenQuotedIdent, '"', false); err != nil {
				return err
			}

		case l.d.backtickIdentifiers && c == '`':
			if err := l.quoted(tokenQuotedIdent, '`', false); err != nil {
				return err
			}

		case l.d.bracketIdentifiers && c == '[':
			if err := l.quoted(tokenQuotedIdent, ']', false); err != nil {
				return err
			}

		case l.d.dollarQuoting && c == '$':
			if err := l.dollar(); err != nil {
				return err
			}

		case l.d.atSignVariables && c == '@':
			l.variable()

		case isDigit(c):
			l.number()

		case isWordStart(c) || (l.d.hashIdentifiers && c == '#') || (!l.d.dollarQuoting && c == '$'):
			if err := l.word(); err != nil {
				return err
			}

		case isPunct(c):
			l.emit(tokenPunct, string(c), l.i)
			l.i++

		default:
			return errUnsupportedCharacter
		}
	}
	if l.execDepth > 0 {
		return errUnterminatedComment
	}
	return nil
}

func (l *lexer) peek(n int) byte {
	if l.i+n < len(l.src) {
		return l.src[l.i+n]
	}
	return 0
}

func (l *lexer) emit(kind tokenKind, text string, pos int) {
	l.toks = append(l.toks, token{kind: kind, text: text, lower: strings.ToLower(text), pos: pos})
}

// lineCommentStarts applies MySQL's rule that -- introduces a comment only when
// followed by whitespace, a control character or the end of the statement.
// Elsewhere -- always starts a comment.
func (l *lexer) lineCommentStarts() bool {
	if !l.d.lineCommentNeedsSpace {
		return true
	}
	if l.i+2 >= len(l.src) {
		return true
	}
	c := l.src[l.i+2]
	return isSpace(c) || c < 0x20 || c == 0x7f
}

func (l *lexer) skipLineComment(from int) {
	for from < len(l.src) && l.src[from] != '\n' && l.src[from] != '\r' {
		from++
	}
	l.i = from
}

// blockComment consumes /* ... */. Under MySQL, /*! ... */ and /*!MMMRR ... */
// are not consumed at all: the lexer steps over the introducer and keeps
// scanning, so the contents produce ordinary tokens. The version digits are
// skipped whether or not whitespace follows them, which is the paranoid reading
// of MySQL 8.0.34's rule — treating the contents as live code can only widen
// what the gate inspects.
func (l *lexer) blockComment() error {
	if l.d.executableComments && l.peek(2) == '!' {
		j := l.i + 3
		for j < len(l.src) && isDigit(l.src[j]) {
			j++
		}
		l.execDepth++
		l.i = j
		return nil
	}
	depth := 1
	j := l.i + 2
	for j < len(l.src) {
		if l.d.nestedBlockComments && l.src[j] == '/' && j+1 < len(l.src) && l.src[j+1] == '*' {
			depth++
			j += 2
			continue
		}
		if l.src[j] == '*' && j+1 < len(l.src) && l.src[j+1] == '/' {
			depth--
			j += 2
			if depth == 0 {
				l.i = j
				return nil
			}
			continue
		}
		j++
	}
	return errUnterminatedComment
}

// quoted consumes a delimited run starting at the current position, up to the
// close delimiter — which for T-SQL's [ident]]ifier] differs from the opener. A
// doubled close delimiter is content, as it is in all three engines for both
// string literals and delimited identifiers; backslash escaping is enabled only
// where the dialect says so.
func (l *lexer) quoted(kind tokenKind, close byte, backslash bool) error {
	pos := l.i
	var b strings.Builder
	j := l.i + 1
	for j < len(l.src) {
		c := l.src[j]
		if backslash && c == '\\' && j+1 < len(l.src) {
			b.WriteByte(l.src[j+1])
			j += 2
			continue
		}
		if c == close {
			if j+1 < len(l.src) && l.src[j+1] == close {
				b.WriteByte(close)
				j += 2
				continue
			}
			l.i = j + 1
			l.emit(kind, b.String(), pos)
			return nil
		}
		b.WriteByte(c)
		j++
	}
	if kind == tokenQuotedIdent {
		return errUnterminatedIdentifier
	}
	return errUnterminatedString
}

// dollar handles PostgreSQL's three uses of '$': a positional parameter ($1), a
// dollar-quoted string ($$ ... $$ or $tag$ ... $tag$) whose contents are taken
// completely literally, and the bare operator character. A tag follows
// identifier rules and cannot begin with a digit, which is the whole
// disambiguation between the first two.
func (l *lexer) dollar() error {
	pos := l.i
	if isDigit(l.peek(1)) {
		j := l.i + 1
		for j < len(l.src) && isDigit(l.src[j]) {
			j++
		}
		l.emit(tokenVariable, l.src[l.i:j], pos)
		l.i = j
		return nil
	}
	j := l.i + 1
	for j < len(l.src) && isTagPart(l.src[j]) {
		j++
	}
	if j >= len(l.src) || l.src[j] != '$' {
		l.emit(tokenPunct, "$", pos)
		l.i++
		return nil
	}
	tag := l.src[l.i : j+1]
	rest := l.src[j+1:]
	end := strings.Index(rest, tag)
	if end < 0 {
		return errUnterminatedString
	}
	l.emit(tokenString, rest[:end], pos)
	l.i = j + 1 + end + len(tag)
	return nil
}

func (l *lexer) variable() {
	pos := l.i
	j := l.i + 1
	if j < len(l.src) && l.src[j] == '@' {
		j++
	}
	for j < len(l.src) && isWordPart(l.src[j]) {
		j++
	}
	l.emit(tokenVariable, l.src[l.i:j], pos)
	l.i = j
}

func (l *lexer) number() {
	pos := l.i
	j := l.i
	if l.src[j] == '0' && j+1 < len(l.src) && (l.src[j+1] == 'x' || l.src[j+1] == 'X') {
		j += 2
		for j < len(l.src) && isHexDigit(l.src[j]) {
			j++
		}
		l.emit(tokenNumber, l.src[l.i:j], pos)
		l.i = j
		return
	}
	for j < len(l.src) && isDigit(l.src[j]) {
		j++
	}
	if j < len(l.src) && l.src[j] == '.' {
		j++
		for j < len(l.src) && isDigit(l.src[j]) {
			j++
		}
	}
	if j < len(l.src) && (l.src[j] == 'e' || l.src[j] == 'E') {
		k := j + 1
		if k < len(l.src) && (l.src[k] == '+' || l.src[k] == '-') {
			k++
		}
		if k < len(l.src) && isDigit(l.src[k]) {
			for k < len(l.src) && isDigit(l.src[k]) {
				k++
			}
			j = k
		}
	}
	l.emit(tokenNumber, l.src[l.i:j], pos)
	l.i = j
}

// word consumes an unquoted word, or the literal that word introduces when it is
// one of the dialect's literal prefixes: N'...' (T-SQL, MySQL), E'...' and
// U&'...' / U&"..." (PostgreSQL), X'...' and B'...' (MySQL, PostgreSQL).
// Getting a prefix wrong would leave the lexer looking for the end of the string
// one character late, which is how a keyword hides.
func (l *lexer) word() error {
	pos := l.i
	j := l.i
	for j < len(l.src) && (isWordPart(l.src[j]) || (l.d.hashIdentifiers && l.src[j] == '#')) {
		j++
	}
	text := l.src[l.i:j]
	switch strings.ToLower(text) {
	case "n":
		if l.d.nationalPrefix && j < len(l.src) && l.src[j] == '\'' {
			l.i = j
			return l.quoted(tokenString, '\'', l.d.backslashEscapes)
		}
	case "e":
		if l.d.escapeStringPrefix && j < len(l.src) && l.src[j] == '\'' {
			l.i = j
			return l.quoted(tokenString, '\'', true)
		}
	case "u":
		// U&'...' and U&"..." accept an optional UESCAPE 'x' clause that moves
		// the unicode escape character, but never the quote escape: the closing
		// delimiter is still escaped by doubling, so the token boundary does not
		// depend on UESCAPE.
		if l.d.unicodePrefix && j+1 < len(l.src) && l.src[j] == '&' {
			switch l.src[j+1] {
			case '\'':
				l.i = j + 1
				return l.quoted(tokenString, '\'', false)
			case '"':
				l.i = j + 1
				return l.quoted(tokenQuotedIdent, '"', false)
			}
		}
	case "x", "b":
		if l.d.binaryPrefix && j < len(l.src) && l.src[j] == '\'' {
			l.i = j
			return l.quoted(tokenString, '\'', false)
		}
	}
	l.emit(tokenWord, text, pos)
	l.i = j
	return nil
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isWordStart accepts every byte >= 0x80 so that a UTF-8 identifier is one
// token rather than a run of unsupported characters.
func isWordStart(c byte) bool { return isLetter(c) || c == '_' || c >= 0x80 }

func isWordPart(c byte) bool { return isWordStart(c) || isDigit(c) || c == '$' }

// isTagPart excludes '$' from a dollar-quote tag, unlike isWordPart: the tag
// follows identifier rules and the next '$' is the end of the opener, so $$ has
// the empty tag rather than a tag consisting of a dollar sign.
func isTagPart(c byte) bool { return isWordStart(c) || isDigit(c) }

// isPunct deliberately omits the backslash and the backtick. Neither is
// punctuation in any of the three dialects outside a literal, so reaching one
// here — MySQL's client-side \G separator, a backtick on a non-MySQL
// connection — means the statement is not what the tokenizer thinks it is, and
// an unsupported-character error is the fail-closed answer.
func isPunct(c byte) bool {
	return strings.IndexByte("+-*/%^&|~!=<>(),.;:?[]{}@#$", c) >= 0
}
