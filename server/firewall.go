package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sshlogger/internal/model"
	"strings"
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
		if p.Mode == "allowlist" {
			var capable int
			e = tx.QueryRowContext(r.Context(), "SELECT capable FROM firewall_policies WHERE server_id=?", r.PathValue("id")).Scan(&capable)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if capable < 2 {
				message = "화이트리스트를 지원하는 에이전트로 업데이트한 뒤 다시 시도하세요."
				return invalid
			}
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
		if p.Mode != "" {
			return errors.New("화이트리스트 전환 후에는 허용 IP 목록에서 접근을 관리하세요.")
		}
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
		Mode      *string  `json:"mode"`
	}
	if !decode(w, r, &b) {
		return
	}
	for i, ip := range b.Protected {
		canonical, err := model.CanonicalIP(ip)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		b.Protected[i] = canonical
	}
	a.changeFirewall(w, r, "", "settings", func(p *model.FirewallPolicy) error {
		p.Ports = b.Ports
		if b.Protected != nil {
			p.Protected = b.Protected
		}
		if b.Mode != nil {
			if *b.Mode != "allowlist" && *b.Mode != "off" {
				return errors.New("접근 정책은 allowlist 또는 off로 설정하세요.")
			}
			p.Mode = *b.Mode
			p.Bans = []model.IPBan{}
		}
		return nil
	})
}

func (a *App) allowIP(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IP   string  `json:"ip"`
		Name *string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	ip, err := model.CanonicalIP(b.IP)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.changeFirewall(w, r, ip, "allow", func(p *model.FirewallPolicy) error {
		setAllowedName(p, ip, b.Name)
		for _, existing := range p.Allowed {
			if existing == ip {
				return nil
			}
		}
		p.Allowed = append(p.Allowed, ip)
		return nil
	})
}

// Names are optional metadata; keep the allowed address array compatible with existing agents.
func setAllowedName(p *model.FirewallPolicy, ip string, name *string) {
	if name == nil {
		return
	}
	value := strings.TrimSpace(*name)
	if value == "" {
		delete(p.AllowedNames, ip)
		return
	}
	if p.AllowedNames == nil {
		p.AllowedNames = map[string]string{}
	}
	p.AllowedNames[ip] = value
}

func (a *App) updateAllowedIP(w http.ResponseWriter, r *http.Request) {
	ip, err := model.CanonicalIP(r.PathValue("ip"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var b struct {
		Name *string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Name == nil {
		fail(w, 400, "변경할 이름을 입력하세요.")
		return
	}
	a.changeFirewall(w, r, ip, "update_allow", func(p *model.FirewallPolicy) error {
		for _, existing := range p.Allowed {
			if existing == ip {
				setAllowedName(p, ip, b.Name)
				return nil
			}
		}
		return errors.New("등록된 허용 IP를 찾을 수 없습니다.")
	})
}

func (a *App) removeAllowedIP(w http.ResponseWriter, r *http.Request) {
	ip, err := model.CanonicalIP(r.PathValue("ip"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.changeFirewall(w, r, ip, "remove_allow", func(p *model.FirewallPolicy) error {
		allowed := []string{}
		for _, existing := range p.Allowed {
			if existing != ip {
				allowed = append(allowed, existing)
			}
		}
		p.Allowed = allowed
		delete(p.AllowedNames, ip)
		return nil
	})
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
	// 0: unavailable, 1: legacy denylist, 2: allowlist + legacy support.
	capable := 0
	if b.CanFirewall {
		capable = 1
		if b.CanAllowlist {
			capable = 2
		}
	}
	compatible := b.CanFirewall && (p.Mode != "allowlist" || b.CanAllowlist)
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO firewall_policies(server_id,revision,policy,capable) VALUES(?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET capable=excluded.capable", server, p.Revision, string(raw), capable); err != nil {
		return nil, err
	}
	if result := b.FirewallResult; result != nil && result.Revision == p.Revision {
		applied := ""
		status := "failed"
		if result.Error == "" && compatible {
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
	// Never send an allowlist to an older agent: it would ignore the new fields
	// and replace its table with an empty denylist, silently opening access.
	if !compatible {
		return nil, nil
	}
	return &p, nil
}
