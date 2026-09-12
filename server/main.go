package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	restore := flag.String("restore", "", "restore snapshot while all server instances are stopped")
	backup := flag.String("backup", "", "write consistent SQLite snapshot to a NEW path")
	health := flag.Bool("healthcheck", false, "probe local service")
	flag.Parse()
	if *health {
		c := http.Client{Timeout: 3 * time.Second}
		r, e := c.Get("http://127.0.0.1:8080/api/health")
		if e != nil {
			os.Exit(1)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	path := env("DB_PATH", "data/sshlogger.db")
	if *restore != "" {
		if e := restoreSnapshot(path, *restore); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Restore complete")
		return
	}
	s, e := openStore(path)
	if e != nil {
		log.Fatal(e)
	}
	defer s.db.Close()
	if *backup != "" {
		dest, e := filepath.Abs(*backup)
		if e != nil {
			log.Fatal(e)
		}
		if _, e = os.Stat(dest); !os.IsNotExist(e) {
			log.Fatal("backup path must not exist")
		}
		if _, e = s.db.Exec("VACUUM INTO ?", dest); e != nil {
			log.Fatal(e)
		}
		if e = os.Chmod(dest, 0600); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Backup created:", dest)
		return
	}
	var n int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&n); e != nil {
		log.Fatal(e)
	}
	if n == 0 {
		pass := os.Getenv("ADMIN_PASSWORD")
		if f := os.Getenv("ADMIN_PASSWORD_FILE"); f != "" {
			b, e := os.ReadFile(f)
			if e != nil {
				log.Fatal(e)
			}
			pass = strings.TrimSpace(string(b))
		}
		if len(pass) < 12 || len(pass) > 72 {
			log.Fatal("initial ADMIN_PASSWORD must contain 12–72 bytes (or set ADMIN_PASSWORD_FILE)")
		}
		h, e := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if e != nil {
			log.Fatal(e)
		}
		if e = s.transaction(context.Background(), func(tx *sql.Tx) error {
			if _, err := tx.Exec("INSERT INTO admins VALUES(?,?)", env("ADMIN_USER", "admin"), string(h)); err != nil {
				return err
			}
			_, err := tx.Exec("INSERT INTO admin_roles VALUES(?,'super_admin')", env("ADMIN_USER", "admin"))
			return err
		}); e != nil {
			log.Fatal(e)
		}
	}
	a := &App{store: s, origin: strings.TrimRight(env("PUBLIC_ORIGIN", "http://localhost:8080"), "/"), secure: strings.HasPrefix(env("PUBLIC_ORIGIN", "http://localhost:8080"), "https://"), webDir: env("WEB_DIR", "web/dist")}
	srv := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c, cancel := context.WithTimeout(ctx, 10*time.Second)
				if e := s.cleanup(c); e != nil {
					log.Printf("retention: %v", e)
				}
				cancel()
				_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
			}
		}
	}()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	log.Printf("SSH Logger listening on %s", srv.Addr)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
