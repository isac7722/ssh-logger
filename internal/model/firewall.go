package model

import (
	"fmt"
	"net/netip"
	"unicode/utf8"
)

type IPBan struct {
	IP         string `json:"ip"`
	Disconnect bool   `json:"disconnect"`
}
type FirewallPolicy struct {
	Revision     string            `json:"revision"`
	Mode         string            `json:"mode,omitempty"` // Empty is the legacy denylist policy.
	Allowed      []string          `json:"allowed,omitempty"`
	AllowedNames map[string]string `json:"allowed_names,omitempty"`
	Ports        []int             `json:"ports"`
	Protected    []string          `json:"protected"`
	Bans         []IPBan           `json:"bans"`
}
type FirewallResult struct {
	Revision string `json:"revision"`
	Error    string `json:"error"`
}

func CanonicalIP(raw string) (string, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("IPv4 또는 IPv6 주소를 입력하세요.")
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return "", fmt.Errorf("루프백·멀티캐스트·미지정 주소는 사용할 수 없습니다.")
	}
	return ip.String(), nil
}
func (p FirewallPolicy) Validate() error {
	if p.Mode != "" && p.Mode != "allowlist" && p.Mode != "off" {
		return fmt.Errorf("알 수 없는 SSH 접근 정책입니다.")
	}
	if p.Mode != "" && len(p.Bans) > 0 {
		return fmt.Errorf("화이트리스트와 기존 차단 규칙을 함께 적용할 수 없습니다.")
	}
	if p.Mode == "allowlist" && len(p.Allowed) == 0 {
		return fmt.Errorf("화이트리스트를 사용하려면 허용 IP가 최소 1개 필요합니다.")
	}
	if len(p.Allowed) > 1000 {
		return fmt.Errorf("허용 IP는 최대 1000개까지 등록할 수 있습니다.")
	}
	allowed := map[string]bool{}
	for _, ip := range p.Allowed {
		v, e := CanonicalIP(ip)
		if e != nil || v != ip || allowed[ip] {
			return fmt.Errorf("중복 또는 잘못된 허용 IP입니다.")
		}
		allowed[ip] = true
	}
	for ip, name := range p.AllowedNames {
		if !allowed[ip] || utf8.RuneCountInString(name) > 100 {
			return fmt.Errorf("허용 IP 이름은 등록된 IP에만 지정할 수 있으며 최대 100자입니다.")
		}
	}
	if p.Revision == "" || len(p.Revision) > 100 || len(p.Ports) == 0 || len(p.Ports) > 32 || len(p.Protected) > 1000 || len(p.Bans) > 1000 {
		return fmt.Errorf("잘못된 방화벽 정책입니다.")
	}
	for _, port := range p.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("SSH 포트는 1–65535여야 합니다.")
		}
	}
	protected := map[string]bool{}
	for _, ip := range p.Protected {
		v, e := CanonicalIP(ip)
		if e != nil || v != ip {
			return fmt.Errorf("잘못된 보호 IP입니다.")
		}
		protected[ip] = true
	}
	seen := map[string]bool{}
	for _, b := range p.Bans {
		v, e := CanonicalIP(b.IP)
		if e != nil || v != b.IP || protected[b.IP] || seen[b.IP] {
			return fmt.Errorf("중복·보호 IP 또는 잘못된 차단 IP입니다.")
		}
		seen[b.IP] = true
	}
	return nil
}
