package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sshlogger/internal/model"
	"strconv"
	"strings"
	"time"
)

func firewallAvailable() bool { _, err := exec.LookPath("nft"); return os.Geteuid() == 0 && err == nil }

// All interpolated values are validated literals; no shell is involved. One nft
// transaction replaces only our table, leaving other firewall owners untouched.
func firewallScript(p model.FirewallPolicy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	ports := []string{}
	for _, port := range p.Ports {
		ports = append(ports, strconv.Itoa(port))
	}
	var out strings.Builder
	out.WriteString("add table inet ssh_logger\ndelete table inet ssh_logger\nadd table inet ssh_logger\nadd chain inet ssh_logger input { type filter hook input priority -10; policy accept; }\n")
	for _, b := range p.Bans {
		family := "ip"
		if strings.Contains(b.IP, ":") {
			family = "ip6"
		}
		state := "tcp flags & (syn | ack) == syn "
		if b.Disconnect {
			state = ""
		}
		fmt.Fprintf(&out, "add rule inet ssh_logger input %s saddr %s tcp dport { %s } %sdrop\n", family, b.IP, strings.Join(ports, ", "), state)
	}
	return out.String(), nil
}
func applyFirewall(ctx context.Context, p model.FirewallPolicy) error {
	script, err := firewallScript(p)
	if err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft 적용 실패: %v: %.350s", err, output)
	}
	return nil
}
func (s *spool) saveFirewall(p model.FirewallPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO firewall_cache VALUES(1,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy", string(raw))
	return err
}
func (s *spool) cachedFirewall() (*model.FirewallPolicy, error) {
	var raw string
	err := s.db.QueryRow("SELECT policy FROM firewall_cache WHERE id=1").Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p model.FirewallPolicy
	if err = json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	return &p, p.Validate()
}
func reconcileFirewall(ctx context.Context, s *spool, p model.FirewallPolicy) *model.FirewallResult {
	result := &model.FirewallResult{Revision: p.Revision}
	// Persist desired state before applying, so a crash cannot resurrect an old ban.
	if err := s.saveFirewall(p); err != nil {
		result.Error = "방화벽 정책 로컬 저장 실패"
		return result
	}
	if err := applyFirewall(ctx, p); err != nil {
		result.Error = err.Error()
	}
	return result
}
