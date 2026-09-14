package main

import "fmt"

const currentSchemaVersion = 6

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
	if version < 4 {
		for _, q := range []string{
			"CREATE TABLE IF NOT EXISTS server_control(server_id TEXT PRIMARY KEY REFERENCES servers(id),enabled INTEGER NOT NULL)",
			"CREATE TABLE IF NOT EXISTS session_terminations(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES servers(id),session_id TEXT NOT NULL,requested_by TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '')",
			"CREATE INDEX IF NOT EXISTS termination_session ON session_terminations(server_id,session_id,created DESC)",
			"UPDATE schema_version SET version=4",
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	if version < 5 {
		for _, q := range []string{
			"CREATE TABLE IF NOT EXISTS admin_roles(username TEXT PRIMARY KEY REFERENCES admins(username),role TEXT NOT NULL CHECK(role IN ('super_admin','admin')))",
			"INSERT OR IGNORE INTO admin_roles SELECT username,'super_admin' FROM admins",
			"CREATE TABLE IF NOT EXISTS admin_servers(username TEXT NOT NULL REFERENCES admins(username),server_id TEXT NOT NULL REFERENCES servers(id),PRIMARY KEY(username,server_id))",
			"CREATE TABLE IF NOT EXISTS firewall_policies(server_id TEXT PRIMARY KEY REFERENCES servers(id),revision TEXT NOT NULL,policy TEXT NOT NULL,applied_revision TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',reported INTEGER NOT NULL DEFAULT 0,capable INTEGER NOT NULL DEFAULT 0)",
			"CREATE TABLE IF NOT EXISTS firewall_history(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES servers(id),revision TEXT NOT NULL,ip TEXT NOT NULL,action TEXT NOT NULL,requested_by TEXT NOT NULL,created INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',error TEXT NOT NULL DEFAULT '')",
			"CREATE INDEX IF NOT EXISTS firewall_history_server ON firewall_history(server_id,created DESC)",
			"UPDATE schema_version SET version=5",
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	if version < 6 {
		for _, q := range []string{
			"CREATE TABLE account_auth(username TEXT PRIMARY KEY REFERENCES admins(username) ON DELETE CASCADE,user_id TEXT NOT NULL UNIQUE,version INTEGER NOT NULL DEFAULT 0)",
			"CREATE TABLE passkeys(id TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,rp_id TEXT NOT NULL,credential TEXT NOT NULL,name TEXT NOT NULL,created INTEGER NOT NULL,last_used INTEGER NOT NULL DEFAULT 0)",
			"CREATE INDEX passkeys_username ON passkeys(username)",
			"CREATE TABLE auth_pending(id_hash TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,expires INTEGER NOT NULL,data TEXT NOT NULL)",
			"CREATE INDEX auth_pending_username ON auth_pending(username)",
			"CREATE TABLE auth_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,reset INTEGER NOT NULL)",
			"UPDATE schema_version SET version=6",
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
