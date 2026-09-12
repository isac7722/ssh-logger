package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sshlogger/internal/model"
	"strings"
	"testing"
	"time"
)

func TestFirewallValidationAndPersistence(t *testing.T) {
	p := model.FirewallPolicy{Revision: "revision1", Ports: []int{2222}, Protected: []string{"192.0.2.1"}, Bans: []model.IPBan{{IP: "203.0.113.1"}, {IP: "2001:db8::1", Disconnect: true}}}
	script, err := firewallScript(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"ip saddr 203.0.113.1 tcp dport { 2222 } tcp flags & (syn | ack) == syn drop", "ip6 saddr 2001:db8::1 tcp dport { 2222 } drop"} {
		if !strings.Contains(script, part) {
			t.Fatal(script)
		}
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("global firewall mutation")
	}
	path := filepath.Join(t.TempDir(), "spool.db")
	s, err := openSpool(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.saveFirewall(p); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	s, err = openSpool(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	got, err := s.cachedFirewall()
	if err != nil || !reflect.DeepEqual(*got, p) {
		t.Fatal(got, err)
	}
	p.Revision = "unban"
	p.Bans = []model.IPBan{}
	if err = s.saveFirewall(p); err != nil {
		t.Fatal(err)
	}
	got, err = s.cachedFirewall()
	if err != nil || len(got.Bans) != 0 {
		t.Fatal(got, err)
	}
	for _, ip := range []string{"192.0.2.1", "203.0.113.1; flush ruleset", "::ffff:192.0.2.1", "127.0.0.1"} {
		p.Bans = []model.IPBan{{IP: ip}}
		if _, err = firewallScript(p); err == nil {
			t.Fatal("unsafe IP accepted", ip)
		}
	}
	p.Bans = nil
	p.Ports = []int{0}
	if _, err = firewallScript(p); err == nil {
		t.Fatal("invalid port accepted")
	}
}

// Run only in a disposable container with its own network namespace and NET_ADMIN.
func TestFirewallKernelLifecycle(t *testing.T) {
	if os.Getenv("SSHLOGGER_FIREWALL_TEST") != "disposable" {
		t.Skip("requires disposable network namespace")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, e := exec.Command(name, args...).CombinedOutput(); e != nil {
			t.Fatal(e, string(out))
		}
	}
	run("ip", "addr", "add", "192.0.2.10/32", "dev", "lo")
	run("ip", "addr", "add", "192.0.2.20/32", "dev", "lo")
	run("nft", "add", "table", "inet", "other_owner")
	defer exec.Command("nft", "delete", "table", "inet", "ssh_logger").Run()
	listener, err := net.Listen("tcp4", "192.0.2.20:2222")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 1)
				for {
					if _, e := c.Read(b); e != nil {
						return
					}
					if _, e := c.Write(b); e != nil {
						return
					}
				}
			}()
		}
	}()
	dial := func() (net.Conn, error) {
		return (&net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}}).Dial("tcp4", listener.Addr().String())
	}
	exchange := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, e := c.Write([]byte{1}); e != nil {
			return e
		}
		b := make([]byte, 1)
		_, e := c.Read(b)
		return e
	}
	existing, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	if err = exchange(existing); err != nil {
		t.Fatal(err)
	}
	p := model.FirewallPolicy{Revision: "1", Ports: []int{2222}, Bans: []model.IPBan{{IP: "192.0.2.10"}}}
	apply := func() {
		t.Helper()
		if e := applyFirewall(context.Background(), p); e != nil {
			t.Fatal(e)
		}
	}
	apply()
	apply() // Retry is idempotent.
	if c, e := dial(); e == nil {
		c.Close()
		t.Fatal("new SSH connection bypassed ban")
	}
	if e := exchange(existing); e != nil {
		t.Fatal("existing connection interrupted by new-only ban", e)
	}
	p.Bans[0].Disconnect = true
	apply()
	if e := exchange(existing); e == nil {
		t.Fatal("existing SSH traffic not blocked")
	}
	p.Bans = nil
	apply()
	c, err := dial()
	if err != nil {
		t.Fatal("unban did not restore access", err)
	}
	defer c.Close()
	if err = exchange(c); err != nil {
		t.Fatal(err)
	}
	run("nft", "list", "table", "inet", "other_owner")
	// A persisted ban can be reconstructed after a lost kernel ruleset/restart.
	p.Bans = []model.IPBan{{IP: "192.0.2.10"}}
	s, e := openSpool(filepath.Join(t.TempDir(), "spool.db"), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	if e = s.saveFirewall(p); e != nil {
		t.Fatal(e)
	}
	run("nft", "delete", "table", "inet", "ssh_logger")
	cached, e := s.cachedFirewall()
	if e != nil {
		t.Fatal(e)
	}
	result := reconcileFirewall(context.Background(), s, *cached)
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if c, e := dial(); e == nil {
		c.Close()
		t.Fatal("cached ban not restored")
	}
}

func TestFirewallKernelIPv6AndPortScope(t *testing.T) {
	if os.Getenv("SSHLOGGER_FIREWALL_TEST") != "disposable" {
		t.Skip("requires disposable network namespace")
	}
	for _, ip := range []string{"2001:db8::10/128", "2001:db8::20/128"} {
		if out, err := exec.Command("ip", "-6", "addr", "add", ip, "dev", "lo", "nodad").CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	listener, err := net.Listen("tcp6", "[2001:db8::20]:2222")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	other, err := net.Listen("tcp6", "[2001:db8::20]:2223")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	dial := func(addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("2001:db8::10")}}).Dial("tcp6", addr)
	}
	p := model.FirewallPolicy{Revision: "v6", Ports: []int{2222}, Bans: []model.IPBan{{IP: "2001:db8::10"}}}
	if err = applyFirewall(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("nft", "delete", "table", "inet", "ssh_logger").Run()
	if c, e := dial(listener.Addr().String()); e == nil {
		c.Close()
		t.Fatal("IPv6 ban bypassed")
	}
	c, err := dial(other.Addr().String())
	if err != nil {
		t.Fatal("non-SSH port blocked", err)
	}
	c.Close()
	p.Bans = nil
	if err = applyFirewall(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	c, err = dial(listener.Addr().String())
	if err != nil {
		t.Fatal("IPv6 unban failed", err)
	}
	c.Close()
}
