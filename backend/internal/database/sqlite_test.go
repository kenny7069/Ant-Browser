package database

import (
	"path/filepath"
	"testing"
)

func TestMigrateClearsLegacyPluginDefaultInstallFlags(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "database.db"))
	if err != nil {
		t.Fatalf("NewDB returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.GetConn().Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			desc       TEXT NOT NULL DEFAULT '',
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		t.Fatalf("create schema_migrations returned error: %v", err)
	}
	for _, migration := range migrations {
		if migration.version > 16 {
			break
		}
		if err := db.applyMigration(migration); err != nil {
			t.Fatalf("apply migration %d returned error: %v", migration.version, err)
		}
	}
	if _, err := db.GetConn().Exec(`
		INSERT INTO browser_extensions (extension_id, name, install_dir, enabled, default_install)
		VALUES (?, ?, ?, 1, 1)`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "legacy", "legacy"); err != nil {
		t.Fatalf("insert legacy extension returned error: %v", err)
	}

	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	var defaultInstall int
	if err := db.GetConn().QueryRow(`
		SELECT default_install FROM browser_extensions WHERE extension_id = ?`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Scan(&defaultInstall); err != nil {
		t.Fatalf("query default_install returned error: %v", err)
	}
	if defaultInstall != 0 {
		t.Fatalf("default_install = %d, want 0 after legacy cleanup", defaultInstall)
	}
}

func TestMigrateDefaultsNewPluginsToManualInstall(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "database.db"))
	if err != nil {
		t.Fatalf("NewDB returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	if _, err := db.GetConn().Exec(`
		INSERT INTO browser_extensions (extension_id, name, install_dir, enabled)
		VALUES (?, ?, ?, 1)`, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "new", "new"); err != nil {
		t.Fatalf("insert new extension returned error: %v", err)
	}

	var defaultInstall int
	if err := db.GetConn().QueryRow(`
		SELECT default_install FROM browser_extensions WHERE extension_id = ?`, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").Scan(&defaultInstall); err != nil {
		t.Fatalf("query default_install returned error: %v", err)
	}
	if defaultInstall != 0 {
		t.Fatalf("default_install = %d, want 0 for a newly stored plugin", defaultInstall)
	}
}

func TestMigrateCreatesClosedFarmProfileOperationJournal(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "database.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.GetConn().QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version < 19 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	_, err = db.GetConn().Exec(`INSERT INTO farm_profile_create_operations
		(operation_uid, request_uid, command, node_uid, payload_digest, profile_id, profile_incarnation, display_name, core_ref, status, created_at, updated_at)
		VALUES ('op', 'request', 'unknown', 'node', 'digest', 'profile', 'incarnation', 'name', 'core', 'COMPLETED', 'now', 'now')`)
	if err == nil {
		t.Fatal("journal accepted an unknown command")
	}
}
