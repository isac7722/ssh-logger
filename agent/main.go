package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"sshlogger/internal/model"
	"strings"
	"syscall"
	"time"
)

func main() {
	endpoint := flag.String("url", os.Getenv("SSHLOGGER_URL"), "central HTTPS origin")
	tokenFile := flag.String("token-file", "/etc/ssh-logger/token", "token file")
	source := flag.String("audit-log", "/var/log/audit/audit.log", "auditd log path")
	state := flag.String("state", "/var/lib/ssh-logger/spool.db", "persistent spool path")
	limit := flag.Int64("buffer-mib", 64, "queued JSON budget, excluding SQLite overhead")
	fromStart := flag.Bool("from-start", false, "read existing audit log on first start (only current boot fixtures)")
	insecure := flag.Bool("allow-http", false, "allow plaintext HTTP for isolated development")
	flag.Parse()
	u, e := url.Parse(*endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		log.Fatal("url must be an HTTP(S) origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && *insecure) {
		log.Fatal("HTTPS required; --allow-http is for isolated development only")
	}
	if *limit < 1 || *limit > 4096 {
		log.Fatal("buffer-mib must be 1–4096")
	}
	if _, e = readToken(*tokenFile); e != nil {
		log.Fatal(e)
	}
	bootBytes, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		log.Fatal(e)
	}
	boot := strings.TrimSpace(string(bootBytes))
	s, e := openSpool(*state, *limit<<20)
	if e != nil {
		log.Fatal(e)
	}
	defer s.db.Close()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lookup := func(uid string) string {
		if uid == "" {
			return ""
		}
		u, e := user.LookupId(uid)
		if e == nil {
			return u.Username
		}
		return uid
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	next := time.Now()
	delay := 5 * time.Second
	lastCheckpoint := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			health := "ok"
			if e = s.collect(*source, boot, *fromStart, lookup); e != nil {
				health = "audit_read_error"
				log.Printf("audit collection: %v", e)
			}
			if s.cp.Dropped > 0 && health == "ok" {
				health = "collection_gap"
			}
			if time.Now().Before(next) {
				continue
			}
			events, count, e := s.batch()
			if e != nil {
				log.Printf("spool: %v", e)
				continue
			}
			active, e := activeSessions(boot)
			if e != nil {
				health = "session_scan_error"
			}
			b := model.Batch{Events: events, Backlog: count, Dropped: s.cp.Dropped, Health: health, ActiveSessions: active}
			if e = send(ctx, client, strings.TrimRight(*endpoint, "/")+"/api/ingest", *tokenFile, b); e != nil {
				log.Printf("delivery failed (records retained): %v", e)
				next = time.Now().Add(delay)
				delay *= 2
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				continue
			}
			if e = s.ack(events); e != nil {
				log.Printf("acknowledgement: %v", e)
			}
			delay = 5 * time.Second
			next = time.Now().Add(5 * time.Second)
			if time.Since(lastCheckpoint) > time.Minute {
				_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
				lastCheckpoint = time.Now()
			}
		}
	}
}
func readToken(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("empty token file")
	}
	return t, nil
}
func send(ctx context.Context, c *http.Client, url, path string, b model.Batch) error {
	token, e := readToken(path)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	res, e := c.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return nil
}
