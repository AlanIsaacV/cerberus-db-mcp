package db

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"

	"github.com/AlanIsaacV/cerberus-db-mcp/internal/gate"
)

func TestEverySimilarNamesStatementTheGateAllows(t *testing.T) {
	g, err := gate.New("")
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	for _, engine := range gate.Engines() {
		s, ok := similarNamesFor(engine)
		if !ok {
			t.Fatalf("no similar-names statements for %s", engine)
		}
		for name, statement := range map[string]string{"tables": s.tables, "columns": s.columns, "columns in tables": s.columnsInTables} {
			if decision := g.Validate(engine, statement, nil); decision.Verdict != gate.Allow {
				t.Errorf("%s %s statement verdict = %s (%s/%s), want allow", engine, name, decision.Verdict, decision.Reason, decision.RuleID)
			}
		}
	}
}

func TestOnlyMissingGoWritesTheIdentifierAndTheSimilarNames(t *testing.T) {
	const writer = "missing.go"
	fields := map[string]bool{"missing": true, "similar": true}
	written := map[string]bool{}
	fset := gotoken.NewFileSet()
	for _, name := range nonTestFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		report := func(field string, at gotoken.Pos) {
			if name == writer {
				written[field] = true
				return
			}
			t.Errorf("%s:%d writes Error.%s, which Agent() renders verbatim; only %s may write it, after checking it against the statement", name, fset.Position(at).Line, field, writer)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if field, ok := writtenField(lhs, fields); ok {
						report(field, lhs.Pos())
					}
				}
			case *ast.IncDecStmt:
				if field, ok := writtenField(n.X, fields); ok {
					report(field, n.Pos())
				}
			case *ast.UnaryExpr:
				if n.Op == gotoken.AND {
					if field, ok := writtenField(n.X, fields); ok {
						report(field, n.Pos())
					}
				}
			case *ast.CallExpr:
				if fn, ok := n.Fun.(*ast.Ident); ok && fn.Name == "copy" && len(n.Args) > 0 {
					if field, ok := writtenField(n.Args[0], fields); ok {
						report(field, n.Pos())
					}
				}
			case *ast.CompositeLit:
				if typ, ok := n.Type.(*ast.Ident); ok && typ.Name == "Error" {
					for _, elt := range n.Elts {
						if _, keyed := elt.(*ast.KeyValueExpr); !keyed {
							t.Errorf("%s:%d builds an Error without field names, which sets every field including missing and similar", name, fset.Position(elt.Pos()).Line)
							break
						}
					}
				}
				for _, elt := range n.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && fields[key.Name] {
						report(key.Name, kv.Pos())
					}
				}
			}
			return true
		})
	}
	for field := range fields {
		if !written[field] {
			t.Errorf("%s no longer writes Error.%s, so this guard is checking a field that is not there", writer, field)
		}
	}
}

func writtenField(expr ast.Expr, fields map[string]bool) (string, bool) {
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.SelectorExpr:
			return e.Sel.Name, fields[e.Sel.Name]
		default:
			return "", false
		}
	}
}
