package gate

import (
	"slices"
	"testing"
)

// The two tables below are transcribed from the "## The vector catalogue"
// section of the objective draft. They are the correspondence the build
// enforces: a construct named there but absent from baseline.json fails here,
// so the ruleset cannot quietly fall behind the research that produced it.
//
// Each row states the keyword or name the baseline must carry and a statement
// that must be refused because of it.

type catalogueEntry struct {
	name   string // as written in the findings
	match  string // the rule match baseline.json must contain, lowercased
	engine Engine
	probe  string
}

var layerOneKeywords = []catalogueEntry{
	{"INSERT", "insert", MySQL, "INSERT INTO t (a) VALUES (1)"},
	{"UPDATE", "update", MySQL, "UPDATE t SET a = 1"},
	{"DELETE", "delete", MySQL, "DELETE FROM t"},
	{"MERGE", "merge", SQLServer, "MERGE t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"},
	{"REPLACE", "replace", MySQL, "REPLACE INTO t (a) VALUES (1)"},

	{"CREATE", "create", PostgreSQL, "CREATE TABLE t (a INT)"},
	{"ALTER", "alter", PostgreSQL, "ALTER TABLE t ADD COLUMN b INT"},
	{"DROP", "drop", PostgreSQL, "DROP TABLE t"},
	{"TRUNCATE", "truncate", PostgreSQL, "TRUNCATE TABLE t"},
	{"RENAME", "rename", MySQL, "RENAME TABLE a TO b"},

	{"EXEC", "exec", SQLServer, "EXEC dbo.p"},
	{"EXECUTE", "execute", SQLServer, "EXECUTE dbo.p"},
	{"CALL", "call", MySQL, "CALL p(1)"},
	{"PREPARE", "prepare", MySQL, "PREPARE s FROM 'SELECT 1'"},
	{"DEALLOCATE", "deallocate", MySQL, "DEALLOCATE PREPARE s"},
	{"DO", "do", PostgreSQL, "DO 'begin end'"},

	{"BEGIN", "begin", SQLServer, "BEGIN TRANSACTION"},
	{"COMMIT", "commit", PostgreSQL, "COMMIT"},
	{"ROLLBACK", "rollback", PostgreSQL, "ROLLBACK"},
	{"SAVE", "save", SQLServer, "SAVE TRANSACTION sp1"},
	{"START", "start", MySQL, "START TRANSACTION"},
	{"SET", "set", MySQL, "SET autocommit = 0"},
	{"USE", "use", SQLServer, "USE master"},
	{"EXECUTE AS", "execute as", SQLServer, "EXECUTE AS LOGIN = 'sa'"},
	{"REVERT", "revert", SQLServer, "REVERT"},

	{"GRANT", "grant", PostgreSQL, "GRANT SELECT ON t TO public"},
	{"REVOKE", "revoke", PostgreSQL, "REVOKE SELECT ON t FROM public"},
	{"DENY", "deny", SQLServer, "DENY SELECT ON dbo.t TO guest"},

	{"FLUSH", "flush", MySQL, "FLUSH PRIVILEGES"},
	{"RESET", "reset", MySQL, "RESET QUERY CACHE"},
	{"INSTALL", "install", MySQL, "INSTALL PLUGIN x SONAME 'x.so'"},
	{"UNINSTALL", "uninstall", MySQL, "UNINSTALL PLUGIN x"},
	{"LOCK", "lock", MySQL, "LOCK TABLES t WRITE"},
	{"UNLOCK", "unlock", MySQL, "UNLOCK TABLES"},
	{"DBCC", "dbcc", SQLServer, "DBCC CHECKDB"},
	{"RECONFIGURE", "reconfigure", SQLServer, "RECONFIGURE"},
	{"BULK", "bulk", SQLServer, "BULK INSERT t FROM 'x'"},
	{"WAITFOR", "waitfor", SQLServer, "WAITFOR DELAY '00:00:10'"},
	{"ALTER SYSTEM", "alter system", PostgreSQL, "ALTER SYSTEM SET work_mem = '1GB'"},
}

var layerTwoConstructs = []catalogueEntry{
	{"SELECT ... INTO", "into", SQLServer, "SELECT a INTO copy_of_t FROM t"},
	{"SELECT ... INTO OUTFILE", "into outfile", MySQL, "SELECT * FROM t INTO OUTFILE '/tmp/x'"},
	{"SELECT ... INTO DUMPFILE", "into dumpfile", MySQL, "SELECT a FROM t INTO DUMPFILE '/tmp/x'"},
	{"data-modifying CTE, PostgreSQL shape", "delete", PostgreSQL, "WITH t AS (DELETE FROM x RETURNING *) SELECT * FROM t"},
	{"data-modifying CTE, MySQL shape", "update", MySQL, "WITH c AS (SELECT 1) UPDATE t SET a = 1"},

	{"OPENROWSET", "openrowset", SQLServer, "SELECT * FROM OPENROWSET('p', 'c', 'SELECT 1')"},
	{"OPENQUERY", "openquery", SQLServer, "SELECT * FROM OPENQUERY(l, 'SELECT 1')"},
	{"OPENDATASOURCE", "opendatasource", SQLServer, "SELECT * FROM OPENDATASOURCE('p', 'c').d.s.t"},
	{"xp_cmdshell", "xp_cmdshell", SQLServer, "SELECT * FROM xp_cmdshell('whoami')"},
	{"xp_regwrite", "xp_regwrite", SQLServer, "xp_regwrite 'HKLM', 'a', 'b', 'REG_SZ', 'c'"},
	{"xp_dirtree", "xp_dirtree", SQLServer, "xp_dirtree 'c:'"},
	{"sp_OACreate", "sp_oacreate", SQLServer, "sp_OACreate 'WScript.Shell', @o OUT"},
	{"sp_execute_external_script", "sp_execute_external_script", SQLServer, "sp_execute_external_script @language = N'Python'"},
	{"sp_executesql", "sp_executesql", SQLServer, "sp_executesql N'SELECT 1'"},

	{"pg_read_file", "pg_read_file", PostgreSQL, "SELECT pg_read_file('/etc/passwd')"},
	{"lo_import", "lo_import", PostgreSQL, "SELECT lo_import('/etc/passwd')"},
	{"lo_export", "lo_export", PostgreSQL, "SELECT lo_export(1, '/tmp/x')"},
	{"COPY ... FROM PROGRAM", "from program", PostgreSQL, "COPY t FROM PROGRAM 'id'"},
	{"dblink_exec", "dblink_exec", PostgreSQL, "SELECT dblink_exec('c', 'DROP TABLE t')"},
	{"pg_terminate_backend", "pg_terminate_backend", PostgreSQL, "SELECT pg_terminate_backend(1)"},
	{"nextval", "nextval", PostgreSQL, "SELECT nextval('s')"},
	{"setval", "setval", PostgreSQL, "SELECT setval('s', 1)"},
	{"pg_advisory_lock", "pg_advisory_lock", PostgreSQL, "SELECT pg_advisory_lock(1)"},

	{"LOAD_FILE", "load_file", MySQL, "SELECT LOAD_FILE('/etc/passwd')"},
	{"GET_LOCK", "get_lock", MySQL, "SELECT GET_LOCK('x', 1)"},
	{"sys_exec", "sys_exec", MySQL, "SELECT sys_exec('id')"},

	{"pg_sleep", "pg_sleep", PostgreSQL, "SELECT pg_sleep(1)"},
	{"pg_sleep_for", "pg_sleep_for", PostgreSQL, "SELECT pg_sleep_for('1 second')"},
	{"pg_sleep_until", "pg_sleep_until", PostgreSQL, "SELECT pg_sleep_until(now())"},
	{"SLEEP", "sleep", MySQL, "SELECT SLEEP(5)"},
	{"BENCHMARK", "benchmark", MySQL, "SELECT BENCHMARK(1000000, MD5('x'))"},
}

func TestBaselineIsValid(t *testing.T) {
	rs, err := BaselineRuleset()
	if err != nil {
		t.Fatalf("BaselineRuleset() = %v", err)
	}
	if rs.Version != rulesetVersion {
		t.Fatalf("baseline version = %d, want %d", rs.Version, rulesetVersion)
	}
}

func TestBaselineCoversTheVectorCatalogue(t *testing.T) {
	rs, err := BaselineRuleset()
	if err != nil {
		t.Fatalf("BaselineRuleset() = %v", err)
	}
	g := newTestGate(t)

	matches := map[string]bool{}
	for _, group := range [][]Rule{rs.ForbiddenStatements, rs.ForbiddenFunctions} {
		for _, r := range group {
			matches[r.Match] = true
		}
	}

	for _, layer := range []struct {
		label   string
		entries []catalogueEntry
	}{
		{"layer 1", layerOneKeywords},
		{"layer 2", layerTwoConstructs},
	} {
		for _, e := range layer.entries {
			t.Run(layer.label+"/"+e.name, func(t *testing.T) {
				if !matches[e.match] {
					t.Fatalf("%s is named in the findings but no baseline rule matches %q", e.name, e.match)
				}
				got := g.Validate(e.engine, e.probe, nil)
				if got.Verdict != Deny {
					t.Fatalf("Validate(%s, %q) = %s/%s, want deny for %s", e.engine, e.probe, got.Verdict, got.Reason, e.name)
				}
			})
		}
	}
}

// TestCatalogueProbesAreRefusedOnEveryEngine guards the asymmetry the findings
// call out: a construct that only one engine implements is still refused on the
// others, so a mislabelled connection cannot turn a known write into an
// escalation.
func TestCatalogueProbesAreRefusedOnEveryEngine(t *testing.T) {
	g := newTestGate(t)
	for _, e := range slices.Concat(layerOneKeywords, layerTwoConstructs) {
		t.Run(e.name, func(t *testing.T) {
			for _, engine := range Engines() {
				if got := g.Validate(engine, e.probe, nil); got.Verdict != Deny {
					t.Fatalf("Validate(%s, %q) = %s/%s, want deny", engine, e.probe, got.Verdict, got.Reason)
				}
			}
		})
	}
}
