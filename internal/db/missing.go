package db

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

type missingObject int

const (
	missingTable missingObject = iota + 1
	missingColumn
)

const (
	maxSimilarNames       = 3
	maxSimilarDistance    = 3
	similarNameCandidates = 1000
)

type engineMiss struct {
	object   missingObject
	parts    []string
	position int
}

func engineMissOf(err error) (engineMiss, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		object, ok := map[string]missingObject{"42P01": missingTable, "42703": missingColumn}[pgErr.Code]
		if !ok || pgErr.Position <= 0 || pgErr.InternalPosition != 0 || pgErr.InternalQuery != "" {
			return engineMiss{}, false
		}
		return engineMiss{object: object, parts: nameParts(postgresMissingName(pgErr.Code, pgErr.Message)), position: int(pgErr.Position)}, true
	}
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		object, ok := map[uint16]missingObject{1146: missingTable, 1054: missingColumn}[myErr.Number]
		if !ok {
			return engineMiss{}, false
		}
		return engineMiss{object: object, parts: nameParts(mysqlMissingName(myErr.Number, myErr.Message))}, true
	}
	var msErr mssql.Error
	if errors.As(err, &msErr) {
		object, ok := map[int32]missingObject{208: missingTable, 207: missingColumn}[msErr.Number]
		if !ok {
			return engineMiss{}, false
		}
		return engineMiss{object: object, parts: nameParts(sqlServerMissingName(msErr.Number, msErr.Message))}, true
	}
	return engineMiss{}, false
}

func postgresMissingName(code, message string) string {
	if code == "42P01" {
		return between(message, `relation "`, `" does not exist`)
	}
	if name := between(message, `column "`, `" does not exist`); name != "" {
		return name
	}
	return between(message, "column ", " does not exist")
}

func mysqlMissingName(number uint16, message string) string {
	if number == 1146 {
		return between(message, "Table '", "' doesn't exist")
	}
	rest, ok := strings.CutPrefix(message, "Unknown column '")
	if !ok || !strings.HasSuffix(rest, "'") {
		return ""
	}
	end := strings.LastIndex(rest, "' in '")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func sqlServerMissingName(number int32, message string) string {
	if number == 208 {
		return between(message, "Invalid object name '", "'.")
	}
	return between(message, "Invalid column name '", "'.")
}

func between(message, prefix, suffix string) string {
	rest, ok := strings.CutPrefix(message, prefix)
	if !ok {
		return ""
	}
	name, ok := strings.CutSuffix(rest, suffix)
	if !ok {
		return ""
	}
	return name
}

func nameParts(name string) []string {
	if name == "" {
		return nil
	}
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if !plainName(part) {
			return nil
		}
	}
	return parts
}

func plainName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return r == ' ' || !strconv.IsPrint(r) || strings.ContainsRune("\"'`[]\\.,", r)
	})
}

type stmtTokenKind int

const (
	stmtWord stmtTokenKind = iota + 1
	stmtDelimited
	stmtLiteral
	stmtSymbol
)

type stmtToken struct {
	kind       stmtTokenKind
	text       string
	start, end int
}

func (t stmtToken) isName() bool { return t.kind == stmtWord || t.kind == stmtDelimited }

func (t stmtToken) isWord(word string) bool {
	return t.kind == stmtWord && strings.EqualFold(t.text, word)
}

func (t stmtToken) symbol(s string) bool { return t.kind == stmtSymbol && t.text == s }

func lexStatement(engine gate.Engine, s string) ([]stmtToken, bool) {
	var toks []stmtToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case strings.HasPrefix(s[i:], "--") || (engine == gate.MySQL && c == '#'):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				return toks, true
			}
			i += end + 1
		case strings.HasPrefix(s[i:], "/*"):
			end, ok := blockCommentEnd(engine, s, i)
			if !ok {
				return nil, false
			}
			i = end
		case c == '\'':
			escapes := false
			if n := len(toks); n > 0 && toks[n-1].kind == stmtWord && toks[n-1].end == i && isLiteralPrefix(engine, toks[n-1].text) {
				escapes = engine == gate.PostgreSQL && strings.EqualFold(toks[n-1].text, "e")
				toks = toks[:n-1]
			}
			end, ok := literalEnd(engine, s, i, '\'', escapes)
			if !ok {
				return nil, false
			}
			toks = append(toks, stmtToken{kind: stmtLiteral, text: s[i:end], start: i, end: end})
			i = end
		case c == '"' && engine != gate.PostgreSQL:
			end, ok := literalEnd(engine, s, i, '"', false)
			if !ok {
				return nil, false
			}
			toks = append(toks, stmtToken{kind: stmtLiteral, text: s[i:end], start: i, end: end})
			i = end
		case c == '"' || (c == '`' && engine == gate.MySQL) || (c == '[' && engine == gate.SQLServer):
			closing := c
			if c == '[' {
				closing = ']'
			}
			bare, end, ok := delimitedEnd(s, i, closing)
			if !ok {
				return nil, false
			}
			toks = append(toks, stmtToken{kind: stmtDelimited, text: bare, start: i, end: end})
			i = end
		case c == '$' && engine == gate.PostgreSQL:
			end, ok := dollarEnd(s, i)
			if !ok {
				return nil, false
			}
			kind := stmtLiteral
			if end == i+1 || isDigit(s[i+1]) {
				kind = stmtSymbol
			}
			toks = append(toks, stmtToken{kind: kind, text: s[i:end], start: i, end: end})
			i = end
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if !isIdentifierRune(r) {
				toks = append(toks, stmtToken{kind: stmtSymbol, text: s[i : i+size], start: i, end: i + size})
				i += size
				continue
			}
			end := i
			for end < len(s) {
				r, size := utf8.DecodeRuneInString(s[end:])
				if !isIdentifierRune(r) {
					break
				}
				end += size
			}
			toks = append(toks, stmtToken{kind: stmtWord, text: s[i:end], start: i, end: end})
			i = end
		}
	}
	return toks, true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isIdentifierRune(r rune) bool {
	return r == '_' || r == '$' ||
		('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') ||
		r >= utf8.RuneSelf
}

func isLiteralPrefix(engine gate.Engine, word string) bool {
	switch strings.ToLower(word) {
	case "n":
		return true
	case "x", "b":
		return engine != gate.SQLServer
	case "e":
		return engine == gate.PostgreSQL
	}
	return false
}

func blockCommentEnd(engine gate.Engine, s string, i int) (int, bool) {
	if engine == gate.MySQL {
		if strings.HasPrefix(s[i:], "/*!") {
			return 0, false
		}
		end := strings.Index(s[i+2:], "*/")
		if end < 0 {
			return 0, false
		}
		return i + 2 + end + 2, true
	}
	depth := 0
	for j := i; j+1 < len(s); {
		switch {
		case s[j] == '/' && s[j+1] == '*':
			depth++
			j += 2
		case s[j] == '*' && s[j+1] == '/':
			depth--
			j += 2
			if depth == 0 {
				return j, true
			}
		default:
			j++
		}
	}
	return 0, false
}

func literalEnd(engine gate.Engine, s string, i int, quote byte, escapes bool) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			if escapes {
				j++
				continue
			}
			if engine != gate.SQLServer {
				return 0, false
			}
		case quote:
			if j+1 < len(s) && s[j+1] == quote {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return 0, false
}

func delimitedEnd(s string, i int, closing byte) (string, int, bool) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		if s[j] != closing {
			b.WriteByte(s[j])
			continue
		}
		if j+1 < len(s) && s[j+1] == closing {
			b.WriteByte(closing)
			j++
			continue
		}
		return b.String(), j + 1, true
	}
	return "", 0, false
}

func dollarEnd(s string, i int) (int, bool) {
	j := i + 1
	if j < len(s) && isDigit(s[j]) {
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		return j, true
	}
	for j < len(s) {
		r, size := utf8.DecodeRuneInString(s[j:])
		if r == '$' || !isIdentifierRune(r) {
			break
		}
		j += size
	}
	if j >= len(s) || s[j] != '$' {
		return i + 1, true
	}
	tag := s[i : j+1]
	end := strings.Index(s[j+1:], tag)
	if end < 0 {
		return 0, false
	}
	return j + 1 + end + len(tag), true
}

type stmtRef struct {
	parts      []stmtToken
	contiguous bool
}

func (r stmtRef) start() int { return r.parts[0].start }

func (r stmtRef) end() int { return r.parts[len(r.parts)-1].end }

func (r stmtRef) last() stmtToken { return r.parts[len(r.parts)-1] }

func (r stmtRef) qualifier() []stmtToken { return r.parts[:len(r.parts)-1] }

func readRef(toks []stmtToken, i int) (stmtRef, int) {
	ref := stmtRef{parts: []stmtToken{toks[i]}, contiguous: true}
	j := i + 1
	for j+1 < len(toks) && toks[j].symbol(".") && toks[j+1].isName() {
		if toks[j].start != toks[j-1].end || toks[j+1].start != toks[j].end {
			ref.contiguous = false
		}
		ref.parts = append(ref.parts, toks[j+1])
		j += 2
	}
	return ref, j
}

func statementRefs(toks []stmtToken) []stmtRef {
	var refs []stmtRef
	for i := 0; i < len(toks); {
		if !toks[i].isName() {
			i++
			continue
		}
		ref, next := readRef(toks, i)
		refs = append(refs, ref)
		i = next
	}
	return refs
}

func sameName(t stmtToken, name string) bool {
	if t.kind == stmtDelimited {
		return t.text == name
	}
	return strings.EqualFold(t.text, name)
}

func sameToken(a, b stmtToken) bool {
	if a.kind == stmtWord && b.kind == stmtWord {
		return strings.EqualFold(a.text, b.text)
	}
	return a.text == b.text
}

func sameTokens(a, b []stmtToken) bool {
	return slices.EqualFunc(a, b, sameToken)
}

func (r stmtRef) matches(parts []string) (int, bool) {
	k := min(len(r.parts), len(parts))
	if k == 0 {
		return 0, false
	}
	for i := 1; i <= k; i++ {
		if !sameName(r.parts[len(r.parts)-i], parts[len(parts)-i]) {
			return 0, false
		}
	}
	return k, true
}

func (r stmtRef) written(statement string, k int) string {
	tail := r.parts[len(r.parts)-k:]
	unquoted := r.contiguous
	for _, part := range tail {
		if !plainName(part.text) {
			return ""
		}
		unquoted = unquoted && part.kind == stmtWord
	}
	if k > 1 && unquoted {
		return statement[tail[0].start:tail[k-1].end]
	}
	return tail[k-1].text
}

type missingRef struct {
	written   string
	bare      string
	qualifier []stmtToken
	scoped    bool
}

func (m engineMiss) inStatement(toks []stmtToken, statement string) (missingRef, bool) {
	if len(m.parts) == 0 {
		return missingRef{}, false
	}
	refs := statementRefs(toks)
	if m.position > 0 {
		offset := byteOffset(statement, m.position)
		for _, ref := range refs {
			if ref.start() <= offset && offset < ref.end() {
				k, ok := ref.matches(m.parts)
				if !ok {
					return missingRef{}, false
				}
				written := ref.written(statement, k)
				return missingRef{written: written, bare: ref.last().text, qualifier: ref.qualifier(), scoped: true}, written != ""
			}
		}
		return missingRef{}, false
	}
	var matched []stmtRef
	var written []string
	for _, ref := range refs {
		k, ok := ref.matches(m.parts)
		if !ok {
			continue
		}
		w := ref.written(statement, k)
		if w == "" {
			return missingRef{}, false
		}
		matched = append(matched, ref)
		written = append(written, w)
	}
	if len(matched) == 0 {
		return missingRef{}, false
	}
	found := missingRef{bare: matched[0].last().text, qualifier: matched[0].qualifier(), scoped: true}
	for _, ref := range matched[1:] {
		if ref.last().text != found.bare {
			return missingRef{}, false
		}
		if !sameTokens(ref.qualifier(), found.qualifier) {
			found.scoped = false
		}
	}
	found.written = written[0]
	if slices.ContainsFunc(written, func(w string) bool { return w != written[0] }) {
		found.written = found.bare
	}
	return found, true
}

func byteOffset(statement string, position int) int {
	n := 0
	for i := range statement {
		n++
		if n == position {
			return i
		}
	}
	return -1
}

type tableSource struct {
	table []stmtToken
	alias *stmtToken
}

var aliasStopWords = map[string]bool{
	"where": true, "join": true, "inner": true, "left": true, "right": true, "full": true,
	"cross": true, "natural": true, "outer": true, "on": true, "using": true, "group": true,
	"order": true, "having": true, "limit": true, "offset": true, "fetch": true, "union": true,
	"except": true, "intersect": true, "minus": true, "window": true, "for": true, "with": true,
	"tablesample": true, "partition": true, "use": true, "force": true, "ignore": true,
	"straight_join": true, "lateral": true, "into": true, "returning": true, "qualify": true,
	"option": true, "pivot": true, "unpivot": true, "apply": true, "select": true, "from": true,
	"lock": true, "procedure": true, "as": true, "when": true, "then": true, "else": true, "end": true,
}

func skipParens(toks []stmtToken, i int) int {
	depth := 0
	for ; i < len(toks); i++ {
		switch {
		case toks[i].symbol("("):
			depth++
		case toks[i].symbol(")"):
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(toks)
}

func cteNames(toks []stmtToken) []stmtToken {
	var names []stmtToken
	for i := range toks {
		if !toks[i].isWord("with") {
			continue
		}
		j := i + 1
		if j < len(toks) && toks[j].isWord("recursive") {
			j++
		}
		for j < len(toks) && toks[j].isName() {
			names = append(names, toks[j])
			j++
			if j < len(toks) && toks[j].symbol("(") {
				j = skipParens(toks, j)
			}
			if j >= len(toks) || !toks[j].isWord("as") {
				break
			}
			j++
			if j < len(toks) && toks[j].isWord("not") {
				j++
			}
			if j < len(toks) && toks[j].isWord("materialized") {
				j++
			}
			if j >= len(toks) || !toks[j].symbol("(") {
				break
			}
			j = skipParens(toks, j)
			if j >= len(toks) || !toks[j].symbol(",") {
				break
			}
			j++
		}
	}
	return names
}

func tableSources(toks []stmtToken) ([]tableSource, bool) {
	ctes := cteNames(toks)
	var sources []tableSource
	certain := true
	queryContext := []bool{true}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.symbol("("):
			queryContext = append(queryContext, i+1 < len(toks) && (toks[i+1].isWord("select") || toks[i+1].isWord("with")))
			continue
		case t.symbol(")"):
			if len(queryContext) > 1 {
				queryContext = queryContext[:len(queryContext)-1]
			}
			continue
		}
		if !queryContext[len(queryContext)-1] || !(t.isWord("from") || t.isWord("join") || t.isWord("straight_join") || t.isWord("apply")) {
			continue
		}
		if t.isWord("from") && i > 0 && toks[i-1].isWord("distinct") {
			continue
		}
		list := t.isWord("from")
		j := i + 1
		for {
			source, next, ok := readTableSource(toks, j, ctes)
			if !ok {
				certain = false
				break
			}
			sources = append(sources, source)
			j = next
			if !list || j >= len(toks) || !toks[j].symbol(",") {
				break
			}
			j++
		}
	}
	return sources, certain
}

func readTableSource(toks []stmtToken, j int, ctes []stmtToken) (tableSource, int, bool) {
	if j < len(toks) && toks[j].isWord("only") {
		j++
	}
	if j >= len(toks) {
		return tableSource{}, j, false
	}
	var source tableSource
	switch {
	case toks[j].symbol("("):
		j = skipParens(toks, j)
	case toks[j].isName() && !(toks[j].kind == stmtWord && aliasStopWords[strings.ToLower(toks[j].text)]):
		ref, next := readRef(toks, j)
		j = next
		if j < len(toks) && toks[j].symbol("(") {
			j = skipParens(toks, j)
			break
		}
		source.table = ref.parts
		if len(ref.parts) == 1 && slices.ContainsFunc(ctes, func(c stmtToken) bool { return sameToken(c, ref.parts[0]) }) {
			source.table = nil
		}
	default:
		return tableSource{}, j, false
	}
	if j < len(toks) && toks[j].isWord("as") {
		j++
		if j >= len(toks) || !toks[j].isName() {
			return tableSource{}, j, false
		}
	}
	if j < len(toks) && toks[j].isName() && !(toks[j].kind == stmtWord && aliasStopWords[strings.ToLower(toks[j].text)]) {
		alias := toks[j]
		source.alias = &alias
		j++
		if j < len(toks) && toks[j].symbol("(") {
			source.table = nil
			j = skipParens(toks, j)
		}
	}
	return source, j, true
}

func (s tableSource) answersTo(qualifier []stmtToken) bool {
	if s.alias != nil {
		return len(qualifier) == 1 && sameToken(*s.alias, qualifier[0])
	}
	if len(s.table) < len(qualifier) {
		return false
	}
	return sameTokens(s.table[len(s.table)-len(qualifier):], qualifier)
}

func tableEntry(engine gate.Engine, table []stmtToken) (string, bool) {
	tail := table[max(0, len(table)-2):]
	names := make([]string, 0, len(tail))
	for _, part := range tail {
		name := part.text
		if engine == gate.PostgreSQL && part.kind == stmtWord {
			name = asciiLower(name)
		}
		if !plainName(name) {
			return "", false
		}
		names = append(names, name)
	}
	return strings.Join(names, "."), true
}

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

func columnScope(engine gate.Engine, toks []stmtToken, miss missingRef) (string, bool) {
	if !miss.scoped {
		return "", false
	}
	sources, certain := tableSources(toks)
	var chosen []tableSource
	if len(miss.qualifier) == 0 {
		if !certain {
			return "", false
		}
		chosen = sources
	} else {
		for _, s := range sources {
			if s.answersTo(miss.qualifier) {
				chosen = append(chosen, s)
			}
		}
	}
	var entries []string
	for _, s := range chosen {
		if s.table == nil {
			return "", false
		}
		entry, ok := tableEntry(engine, s.table)
		if !ok {
			return "", false
		}
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 || (len(miss.qualifier) > 0 && len(entries) > 1) {
		return "", false
	}
	return strings.Join(entries, ","), true
}

type similarNameStatements struct {
	tables, columns, columnsInTables string
}

func similarNamesFor(engine gate.Engine) (similarNameStatements, bool) {
	statements, ok := map[gate.Engine]similarNameStatements{
		gate.PostgreSQL: {tables: postgresSimilarTables, columns: postgresSimilarColumns, columnsInTables: postgresSimilarColumnsInTables},
		gate.MySQL:      {tables: mysqlSimilarTables, columns: mysqlSimilarColumns, columnsInTables: mysqlSimilarColumnsInTables},
		gate.SQLServer:  {tables: sqlServerSimilarTables, columns: sqlServerSimilarColumns, columnsInTables: sqlServerSimilarColumnsInTables},
	}[engine]
	return statements, ok
}

func (e *Executor) nameMissingObject(ctx context.Context, c conn, failure *Error, statement string, cause error) {
	miss, ok := engineMissOf(cause)
	if !ok {
		return
	}
	engine := c.spec().Engine
	toks, ok := lexStatement(engine, statement)
	if !ok {
		return
	}
	ref, ok := miss.inStatement(toks, statement)
	if !ok {
		return
	}
	failure.missing = ref.written
	statements, ok := similarNamesFor(engine)
	if !ok {
		return
	}
	read, args := statements.tables, []any{ref.bare}
	if miss.object == missingColumn {
		read = statements.columns
		if tables, ok := columnScope(engine, toks, ref); ok {
			if similar, ok := e.similarNames(ctx, c, statements.columnsInTables, ref.bare, []any{ref.bare, tables}); !ok || len(similar) > 0 {
				failure.similar = similar
				return
			}
		}
	}
	failure.similar, _ = e.similarNames(ctx, c, read, ref.bare, args)
}

func (e *Executor) similarNames(ctx context.Context, c conn, statement, name string, args []any) ([]string, bool) {
	spec := c.spec()
	if spec.Database == "" {
		return nil, false
	}
	if e.gate.Validate(spec.Engine, statement, nil).Verdict != gate.Allow {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, e.settings.statementDeadline(spec.Engine))
	defer cancel()
	rows, err := c.query(ctx, statement, similarNameCandidates, args...)
	if err != nil {
		return nil, false
	}
	return closestNames(name, rows.rows), true
}

func closestNames(name string, rows [][]any) []string {
	type candidate struct {
		name     string
		distance int
	}
	limit := min(1+utf8.RuneCountInString(name)/4, maxSimilarDistance)
	target := strings.ToLower(name)
	var found []candidate
	seen := make(map[string]bool)
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		candidateName, ok := schemaText(row[0])
		if !ok || !plainName(candidateName) || candidateName == name || seen[candidateName] {
			continue
		}
		seen[candidateName] = true
		if distance := editDistance(strings.ToLower(candidateName), target); distance <= limit {
			found = append(found, candidate{name: candidateName, distance: distance})
		}
	}
	slices.SortFunc(found, func(a, b candidate) int {
		if a.distance != b.distance {
			return a.distance - b.distance
		}
		return strings.Compare(a.name, b.name)
	})
	out := make([]string, 0, min(len(found), maxSimilarNames))
	for _, f := range found[:min(len(found), maxSimilarNames)] {
		out = append(out, f.name)
	}
	return out
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	previous := make([]int, len(rb)+1)
	current := make([]int, len(rb)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		current[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(rb)]
}
