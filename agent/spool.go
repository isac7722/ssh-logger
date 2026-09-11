package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sort"
	"sshlogger/internal/model"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type checkpoint struct {
	Inode   string `json:"inode"`
	Offset  int64  `json:"offset"`
	Boot    string `json:"boot"`
	Dropped int64  `json:"dropped"`
}
type spool struct {
	db    *sql.DB
	cp    checkpoint
	limit int64
}

func openSpool(path string, limit int64) (*spool, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS queue(id TEXT PRIMARY KEY,payload TEXT NOT NULL);`); e != nil {
		db.Close()
		return nil, e
	}
	s := &spool{db: db, limit: limit}
	var raw string
	e = db.QueryRow("SELECT data FROM checkpoint WHERE id=1").Scan(&raw)
	if e != nil && e != sql.ErrNoRows {
		db.Close()
		return nil, e
	}
	if raw != "" {
		if e = json.Unmarshal([]byte(raw), &s.cp); e != nil {
			db.Close()
			return nil, e
		}
	}
	return s, nil
}
func inode(info os.FileInfo) string {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
	}
	return info.Name()
}
func (s *spool) commit(cp checkpoint, events []model.Event) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var used int64
	if e = tx.QueryRow("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM queue").Scan(&used); e != nil {
		return e
	}
	for _, ev := range events {
		raw, e := json.Marshal(ev)
		if e != nil {
			return e
		}
		var exists int
		if e = tx.QueryRow("SELECT COUNT(*) FROM queue WHERE id=?", ev.ID).Scan(&exists); e != nil {
			return e
		}
		if exists != 0 {
			continue
		}
		// Keep the oldest unacknowledged records. Drop newest on saturation, count losses.
		if len(raw) > 256<<10 || len(ev.Args) > 4096 || len(ev.Program) > 4096 || len(ev.User) > 256 || len(ev.EffectiveUser) > 256 || len(ev.IP) > 100 || used+int64(len(raw)) > s.limit {
			cp.Dropped++
			continue
		}
		if _, e = tx.Exec("INSERT INTO queue VALUES(?,?)", ev.ID, string(raw)); e != nil {
			return e
		}
		used += int64(len(raw))
	}
	raw, _ := json.Marshal(cp)
	if _, e = tx.Exec("INSERT INTO checkpoint VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", string(raw)); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.cp = cp
	return nil
}
func (s *spool) batch() ([]model.Event, int, error) {
	var count int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM queue").Scan(&count); e != nil {
		return nil, 0, e
	}
	rows, e := s.db.Query("SELECT payload FROM queue ORDER BY rowid LIMIT 100")
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []model.Event{}
	size := 0
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return nil, 0, e
		}
		if size+len(raw) > 1<<20 && len(out) > 0 {
			break
		}
		var ev model.Event
		if e = json.Unmarshal([]byte(raw), &ev); e != nil {
			return nil, 0, e
		}
		out = append(out, ev)
		size += len(raw)
	}
	return out, count, rows.Err()
}
func (s *spool) ack(events []model.Event) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, ev := range events {
		if _, e = tx.Exec("DELETE FROM queue WHERE id=?", ev.ID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *spool) collect(path, boot string, fromStart bool, lookup func(string) string) error {
	current, e := os.Stat(path)
	if e != nil {
		return e
	}
	cp := s.cp
	if cp.Inode == "" || cp.Boot != boot {
		if cp.Boot != "" && cp.Boot != boot {
			cp.Dropped++
		}
		cp.Inode = inode(current)
		cp.Boot = boot
		cp.Offset = current.Size()
		if fromStart && s.cp.Inode == "" {
			cp.Offset = 0
		}
		if e = s.commit(cp, nil); e != nil {
			return e
		}
	}
	target := path
	if cp.Inode != inode(current) {
		matches, _ := filepath.Glob(path + "*")
		found := false
		for _, p := range matches {
			st, e := os.Stat(p)
			if e == nil && inode(st) == cp.Inode {
				target = p
				found = true
				break
			}
		}
		if !found {
			cp.Dropped++
			cp.Inode = inode(current)
			cp.Offset = 0
			target = path
		}
	}
	f, e := os.Open(target)
	if e != nil {
		return e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return e
	}
	if stat.Size() < cp.Offset {
		cp.Offset = 0
		cp.Dropped++
	}
	if _, e = f.Seek(cp.Offset, io.SeekStart); e != nil {
		return e
	}
	type group struct {
		records []record
		start   int64
		ended   bool
	}
	groups := map[string]*group{}
	order := []string{}
	offset := cp.Offset
	reader := bufio.NewReaderSize(f, 64<<10)
	for i := 0; i < 10000 && offset-cp.Offset < 4<<20; i++ {
		line, e := reader.ReadString('\n')
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if len(line) > 1<<20 {
			return fmt.Errorf("audit record exceeds 1 MiB")
		}
		start := offset
		offset += int64(len(line))
		r, ok := parseRecord(line)
		if !ok {
			continue
		}
		g := groups[r.id]
		if g == nil {
			g = &group{start: start}
			groups[r.id] = g
			order = append(order, r.id)
		}
		g.records = append(g.records, r)
		if r.kind == "EOE" {
			g.ended = true
		}
	}
	safe := offset
	cutoff := time.Now().Add(-3 * time.Second).UnixMilli()
	for _, id := range order {
		g := groups[id]
		if !g.ended && g.records[0].time > cutoff && g.start < safe {
			safe = g.start
		}
	}
	// The final syscall group may continue beyond this read chunk. Replay it next tick.
	if offset < stat.Size() && len(order) > 0 {
		g := groups[order[len(order)-1]]
		if !g.ended && g.start < safe {
			safe = g.start
		}
	}
	events := []model.Event{}
	for _, id := range order {
		g := groups[id]
		if g.start < safe {
			events = append(events, eventsFor(g.records, boot, lookup)...)
		}
	}
	cp.Offset = safe
	if target != path && safe >= stat.Size() {
		cp.Inode = inode(current)
		cp.Offset = 0
	}
	return s.commit(cp, events)
}
func activeSessions(boot string) ([]string, error) {
	dirs, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	set := map[string]bool{}
	for _, d := range dirs {
		if _, e := strconv.Atoi(d.Name()); e != nil {
			continue
		}
		base := filepath.Join("/proc", d.Name())
		b, e := os.ReadFile(filepath.Join(base, "comm"))
		if os.IsPermission(e) {
			return nil, e
		}
		if e != nil {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "sshd") {
			continue
		}
		b, e = os.ReadFile(filepath.Join(base, "sessionid"))
		if os.IsPermission(e) {
			return nil, e
		}
		if e != nil {
			continue
		}
		id := sessionID(boot, strings.TrimSpace(string(b)))
		if id != "" {
			set[id] = true
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
