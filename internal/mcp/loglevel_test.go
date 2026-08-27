package mcp

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"testing"

	"github.com/rs/zerolog"
)

func TestConfiguredApplicationLoggerCarriesLevel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		level zerolog.Level
		emits bool
	}{
		{name: "debug", level: zerolog.DebugLevel, emits: true},
		{name: "info", level: zerolog.InfoLevel, emits: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			log := NewLogger(&output)
			log = log.Level(tt.level)
			log.Debug().Msg("debug event")

			if !tt.emits {
				if output.Len() != 0 {
					t.Errorf("Debug event wrote %q at %s", output.String(), tt.level)
				}
				return
			}

			var event map[string]any
			if err := json.Unmarshal(output.Bytes(), &event); err != nil {
				t.Fatalf("decode Debug event: %v\n%s", err, output.String())
			}
			if got := event["level"]; got != "debug" {
				t.Errorf("Debug event level = %v, want debug", got)
			}
			if got := event["message"]; got != "debug event" {
				t.Errorf("Debug event message = %v, want debug event", got)
			}
		})
	}
}

func TestMainAppliesTheConfiguredLoggerLevelBeforeLoggerConsumers(t *testing.T) {
	fset, files := parseObjectiveFiles(t)
	mainFile, ok := files[cmdDir+"/main.go"]
	if !ok {
		t.Fatalf("the source scan did not reach %s/main.go", cmdDir)
	}

	var loadConfigs, levelApplications []ast.Node
	for _, declaration := range mainFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "run" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				if isQualifiedCall(node, "mcp", "LoadConfig") {
					loadConfigs = append(loadConfigs, node)
				}
			case *ast.AssignStmt:
				if isConfiguredLoggerLevelAssignment(node) {
					levelApplications = append(levelApplications, node)
				}
			}
			return true
		})
	}

	if len(loadConfigs) != 1 {
		t.Fatalf("run calls mcp.LoadConfig %d times, want once", len(loadConfigs))
	}
	if len(levelApplications) != 1 {
		t.Fatalf("run applies cfg.LogLevel with log = log.Level(cfg.LogLevel) %d times, want once", len(levelApplications))
	}
	loadConfig := loadConfigs[0]
	applyLevel := levelApplications[0]
	if loadConfig.Pos() >= applyLevel.Pos() {
		t.Errorf("mcp.LoadConfig at %s must precede logger level application at %s", fset.Position(loadConfig.Pos()), fset.Position(applyLevel.Pos()))
	}

	for _, declaration := range mainFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "run" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == applyLevel {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !callReceivesLogger(call) {
				return true
			}
			if applyLevel.Pos() >= call.Pos() {
				t.Errorf("logger level application at %s must precede %s at %s", fset.Position(applyLevel.Pos()), callName(call), fset.Position(call.Pos()))
			}
			return true
		})
	}
}

func isQualifiedCall(call *ast.CallExpr, packageName, functionName string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != functionName {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	return ok && qualifier.Name == packageName
}

func callReceivesLogger(call *ast.CallExpr) bool {
	for _, argument := range call.Args {
		identifier, ok := argument.(*ast.Ident)
		if ok && identifier.Name == "log" {
			return true
		}
		literal, ok := argument.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			identifier, ok := field.Value.(*ast.Ident)
			if ok && identifier.Name == "log" {
				return true
			}
		}
	}
	return false
}

func callName(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		qualifier, ok := function.X.(*ast.Ident)
		if ok {
			return qualifier.Name + "." + function.Sel.Name
		}
		return function.Sel.Name
	default:
		return "call"
	}
}

func isConfiguredLoggerLevelAssignment(statement *ast.AssignStmt) bool {
	if statement.Tok.String() != "=" || len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
		return false
	}
	left, ok := statement.Lhs[0].(*ast.Ident)
	if !ok || left.Name != "log" {
		return false
	}
	call, ok := statement.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	method, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || method.Sel.Name != "Level" {
		return false
	}
	receiver, ok := method.X.(*ast.Ident)
	if !ok || receiver.Name != "log" {
		return false
	}
	configuredLevel, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || configuredLevel.Sel.Name != "LogLevel" {
		return false
	}
	configuration, ok := configuredLevel.X.(*ast.Ident)
	return ok && configuration.Name == "cfg"
}
