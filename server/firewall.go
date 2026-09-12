package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sshlogger/internal/model"
	"time"
)

func readPolicy(r *http.Request, tx *sql.Tx, server string) (model.FirewallPolicy, error) {
	p := model.FirewallPolicy{Revision: model.ID(), Ports: []int{22}, Protected: []string{}, Bans: []model.IPBan{}}
	var raw string
	err := tx.QueryRowContext(r.Context(), "SELECT policy FROM firewall_policies WHERE server_id=?", server).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}
func (a *App) firewall(w http.ResponseWriter, r *http.Request) {
	tx, err := a.store.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		fail(w, 503, "방화벽 조회 실패")
		return
	}
	defer tx.Rollback()
	p, err := readPolicy(r, tx, r.PathValue("id"))
	if err != nil {
		fail(w, 503, "방화벽 조회 실패")
		return
	}
	state, err := queryRows(r.Context(), tx, "SELECT applied_revision,error,reported,capable FROM firewall_policies WHERE server_id=?", r.PathValue("id"))
	if err != nil {
		fail(w, 503, "상태 조회 실패")
		return
	}
	history, err := queryRows(r.Context(), tx, "SELECT * FROM firewall_history WHERE server_id=? ORDER BY created DESC,rowid DESC LIMIT 51 OFFSET ?", r.PathValue("id"), page(r)*50)
	if err != nil {
		fail(w, 503, "이력 조회 실패")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 503, "조회 실패")
		return
	}
	reply(w, 200, map[string]any{"policy": p, "state": state, "history": history})
}
func (a *App) changeFirewall(w http.ResponseWriter, r *http.Request, ip, action string, change func(*model.FirewallPolicy) error) {
	invalid := errors.New("invalid")
	message := ""
	revision := model.ID()
	err := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		p, e := readPolicy(r, tx, r.PathValue("id"))
		if e != nil {
			return e
		}
		if e = change(&p); e != nil {
			message = e.Error()
			return invalid
		}
		p.Revision = revision
		if e = p.Validate(); e != nil {
			message = e.Error()
			return invalid
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE firewall_history SET status='superseded' WHERE server_id=? AND status='pending'", r.PathValue("id")); e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), `INSERT INTO firewall_policies(server_id,revision,policy) VALUES(?,?,?) ON CONFLICT(server_id) DO UPDATE SET revision=excluded.revision,policy=excluded.policy,error=''`, r.PathValue("id"), revision, string(raw)); e != nil {
			return e
		}
		_, e = tx.ExecContext(r.Context(), "INSERT INTO firewall_history(id,server_id,revision,ip,action,requested_by,created) VALUES(?,?,?,?,?,?,?)", model.ID(), r.PathValue("id"), revision, ip, action, identity(r).Username, time.Now().UnixMilli())
		return e
	})
	if errors.Is(err, invalid) {
		fail(w, 400, message)
		return
	}
	if err != nil {
		fail(w, 503, "방화벽 요청 저장 실패")
		return
	}
	reply(w, 202, map[string]string{"revision": revision, "status": "pending"})
}
func (a *App) banIP(w http.ResponseWriter, r *http.Request) {
	var b model.IPBan
	if !decode(w, r, &b) {
		return
	}
	ip, err := model.CanonicalIP(b.IP)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	b.IP = ip
	a.changeFirewall(w, r, ip, "ban", func(p *model.FirewallPolicy) error {
		for i, existing := range p.Bans {
			if existing.IP == ip {
				p.Bans[i] = b
				return nil
			}
		}
		p.Bans = append(p.Bans, b)
		return nil
	})
}
func (a *App) unbanIP(w http.ResponseWriter, r *http.Request) {
	ip, err := model.CanonicalIP(r.PathValue("ip"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.changeFirewall(w, r, ip, "unban", func(p *model.FirewallPolicy) error {
		bans := []model.IPBan{}
		for _, b := range p.Bans {
			if b.IP != ip {
				bans = append(bans, b)
			}
		}
		p.Bans = bans
		return nil
	})
}
func (a *App) firewallSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Ports     []int    `json:"ports"`
		Protected []string `json:"protected"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Protected == nil {
		b.Protected = []string{}
	}
	for i, ip := range b.Protected {
		canonical, err := model.CanonicalIP(ip)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		b.Protected[i] = canonical
	}
	a.changeFirewall(w, r, "", "settings", func(p *model.FirewallPolicy) error { p.Ports = b.Ports; p.Protected = b.Protected; return nil })
}
func ingestFirewall(r *http.Request, tx *sql.Tx, server string, b model.Batch, now int64) (*model.FirewallPolicy, error) {
	p, err := readPolicy(r, tx, server)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO firewall_policies(server_id,revision,policy,capable) VALUES(?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET capable=excluded.capable", server, p.Revision, string(raw), b.CanFirewall); err != nil {
		return nil, err
	}
	if result := b.FirewallResult; result != nil && result.Revision == p.Revision {
		applied := ""
		status := "failed"
		if result.Error == "" && b.CanFirewall {
			applied = p.Revision
			status = "succeeded"
		}
		if _, err = tx.ExecContext(r.Context(), "UPDATE firewall_policies SET applied_revision=?,error=?,reported=? WHERE server_id=?", applied, result.Error, now, server); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(r.Context(), "UPDATE firewall_history SET status=?,error=? WHERE server_id=? AND revision=?", status, result.Error, server, p.Revision); err != nil {
			return nil, err
		}
	}
	// Send the complete desired state every heartbeat, including after restarts or lost acknowledgements.
	if !b.CanFirewall {
		return nil, nil
	}
	return &p, nil
}
