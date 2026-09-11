package main

import "fmt"

const currentSchemaVersion = 3

func (s *Store) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		return err
	}
	if version < 1 || version > currentSchemaVersion {
		return fmt.Errorf("unsupported schema version: %d", version)
	}
	if version == 1 {
		// Nullable columns preserve the distinction between legacy/missing IDs and
		// a real PPID 0. The migration never guesses identities for old records.
		for _, q := range []string{
			"ALTER TABLE events ADD COLUMN pid INTEGER CHECK(pid IS NULL OR pid BETWEEN 1 AND 2147483647)",
			"ALTER TABLE events ADD COLUMN ppid INTEGER CHECK(ppid IS NULL OR ppid BETWEEN 0 AND 2147483647)",
			"UPDATE schema_version SET version=2",
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	if version < 3 {
		// Legacy sessions have no account identity; require a fresh login.
		for _, q := range []string{
			"DROP TABLE auth_sessions",
			"CREATE TABLE auth_sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL,username TEXT NOT NULL REFERENCES admins(username))",
			"CREATE INDEX auth_sessions_username ON auth_sessions(username)",
			"UPDATE schema_version SET version=3",
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
