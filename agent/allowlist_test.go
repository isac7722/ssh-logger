package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sshlogger/internal/model"
	"testing"
	"time"
)

// Uses only synthetic addresses inside a disposable container network namespace.
func TestAllowlistKernelConnectionsAndRecovery(t *testing.T) {
	if os.Getenv("SSHLOGGER_FIREWALL_TEST") != "disposable" {
		t.Skip("requires disposable network namespace")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	for _, ip := range []string{"198.51.100.10/32", "198.51.100.11/32", "198.51.100.20/32"} {
		run("ip", "addr", "add", ip, "dev", "lo")
	}
	for _, ip := range []string{"2001:db8:1::10/128", "2001:db8:1::11/128", "2001:db8:1::20/128"} {
		run("ip", "-6", "addr", "add", ip, "dev", "lo", "nodad")
	}
	run("nft", "add", "table", "inet", "allowlist_other_owner")
	defer exec.Command("nft", "delete", "table", "inet", "ssh_logger").Run()
	listen := func(network, host, port string) net.Listener {
		t.Helper()
		listener, err := net.Listen(network, net.JoinHostPort(host, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
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
		return listener
	}
	exchange := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := c.Write([]byte{1}); err != nil {
			return err
		}
		b := make([]byte, 1)
		_, err := c.Read(b)
		return err
	}
	policy := model.FirewallPolicy{Revision: "allow-1", Mode: "allowlist", Ports: []int{2222}, Allowed: []string{"198.51.100.10", "2001:db8:1::10"}}
	apply := func(p model.FirewallPolicy) {
		t.Helper()
		if err := applyFirewall(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range []struct{ network, allowed, denied, host string }{
		{"tcp4", "198.51.100.10", "198.51.100.11", "198.51.100.20"},
		{"tcp6", "2001:db8:1::10", "2001:db8:1::11", "2001:db8:1::20"},
	} {
		t.Run(family.network, func(t *testing.T) {
			ssh := listen(family.network, family.host, "2222")
			other := listen(family.network, family.host, "2223")
			dial := func(source, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 400 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).Dial(family.network, address)
			}
			open := func(source, address string) net.Conn {
				t.Helper()
				c, err := dial(source, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				if err := exchange(c); err != nil {
					t.Fatal(err)
				}
				return c
			}
			blocked := func(source string) {
				t.Helper()
				if c, err := dial(source, ssh.Addr().String()); err == nil {
					c.Close()
					t.Fatal("new non-allowlisted SSH connection succeeded", source)
				}
			}
			off := policy
			off.Mode = "off"
			apply(off)
			existing := open(family.denied, ssh.Addr().String())
			apply(policy)
			apply(policy)
			blocked(family.denied)
			if err := exchange(existing); err != nil {
				t.Fatal("pre-existing connection was interrupted", err)
			}
			approved := open(family.allowed, ssh.Addr().String())
			open(family.denied, other.Addr().String())
			// Removing an allowed source only denies its subsequent connections.
			replacement := policy
			replacement.Allowed = []string{family.denied}
			replacement.Revision = "allow-2"
			apply(replacement)
			blocked(family.allowed)
			if err := exchange(approved); err != nil {
				t.Fatal("removing IP interrupted existing connection", err)
			}
			open(family.denied, ssh.Addr().String())
			// Restore the desired policy from disk after a lost kernel ruleset.
			cachePath := filepath.Join(t.TempDir(), "allowlist.db")
			s, err := openSpool(cachePath, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.saveFirewall(policy); err != nil {
				t.Fatal(err)
			}
			s.db.Close()
			s, err = openSpool(cachePath, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer s.db.Close()
			cached, err := s.cachedFirewall()
			if err != nil || !reflect.DeepEqual(cached, &policy) {
				t.Fatal(cached, err)
			}
			run("nft", "delete", "table", "inet", "ssh_logger")
			if result := reconcileFirewall(context.Background(), s, *cached); result.Error != "" {
				t.Fatal(result.Error)
			}
			blocked(family.denied)
			open(family.allowed, ssh.Addr().String())
			// A list containing only the other IP family must not leave this one open.
			otherFamily := policy
			otherFamily.Allowed = []string{"198.51.100.10"}
			if family.network == "tcp4" {
				otherFamily.Allowed = []string{"2001:db8:1::10"}
			}
			apply(otherFamily)
			blocked(family.allowed)
			blocked(family.denied)
			apply(off)
			open(family.denied, ssh.Addr().String())
		})
	}
	run("nft", "list", "table", "inet", "allowlist_other_owner")
}
