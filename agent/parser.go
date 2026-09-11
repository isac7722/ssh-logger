package main

import (
	"encoding/hex"
	"regexp"
	"sort"
	"sshlogger/internal/model"
	"strconv"
	"strings"
)

var auditHeader = regexp.MustCompile(`type=(\w+).*?msg=audit\((\d+)\.(\d+):(\d+)\)`)
var fieldsRE = regexp.MustCompile(`(?:^|[\s'(])([a-zA-Z0-9_\[\]]+)=("[^"]*"|[^\s')]+)`)
var argRE = regexp.MustCompile(`^a(\d+)$`)
var chunkRE = regexp.MustCompile(`^a(\d+)\[(\d+)\]$`)

type record struct {
	kind, id string
	time     int64
	fields   map[string]string
}

func parseRecord(line string) (record, bool) {
	h := auditHeader.FindStringSubmatch(line)
	if h == nil {
		return record{}, false
	}
	sec, _ := strconv.ParseInt(h[2], 10, 64)
	frac := h[3] + "000"
	ms, _ := strconv.ParseInt(frac[:3], 10, 64)
	f := map[string]string{}
	for _, m := range fieldsRE.FindAllStringSubmatch(line, -1) {
		f[m[1]] = m[2]
	}
	return record{h[1], h[2] + "." + h[3] + ":" + h[4], sec*1000 + ms, f}, true
}
func val(s string) string { return strings.Trim(s, "\"") }
func auditString(s string) string {
	if strings.HasPrefix(s, "\"") {
		return val(s)
	}
	b, e := hex.DecodeString(s)
	if e == nil && len(b) > 0 {
		return string(b)
	}
	return s
}
func sessionID(boot, s string) string {
	if s == "" || s == "4294967295" || s == "-1" {
		return ""
	}
	return boot + ":" + s
}
func eventsFor(records []record, boot string, lookup func(string) string) []model.Event {
	if len(records) == 0 {
		return nil
	}
	base := model.Event{ID: boot + ":" + records[0].id, Time: records[0].time, Args: []string{}}
	var syscall *record
	args := map[int]string{}
	chunks := map[int]map[int]string{}
	hasExec := false
	out := []model.Event{}
	for i := range records {
		r := &records[i]
		f := r.fields
		if r.kind == "SYSCALL" {
			syscall = r
		}
		if r.kind == "EXECVE" {
			hasExec = true
			for k, v := range f {
				if m := argRE.FindStringSubmatch(k); m != nil {
					n, _ := strconv.Atoi(m[1])
					args[n] = auditString(v)
				} else if m := chunkRE.FindStringSubmatch(k); m != nil {
					n, _ := strconv.Atoi(m[1])
					c, _ := strconv.Atoi(m[2])
					if chunks[n] == nil {
						chunks[n] = map[int]string{}
					}
					chunks[n][c] = auditString(v)
				}
			}
		}
		// PAM records from sudo share the login session; only sshd opens/closes SSH sessions.
		exe := auditString(f["exe"])
		if !strings.HasSuffix(exe, "/sshd") && !strings.HasSuffix(exe, "/sshd-session") {
			continue
		}
		e := base
		e.SessionID = sessionID(boot, val(f["ses"]))
		e.PID = processID(f["pid"], 1)
		e.PPID = processID(f["ppid"], 0)
		e.User = auditString(f["acct"])
		e.LoginUID = val(f["auid"])
		e.EffectiveUser = lookup(val(f["uid"]))
		e.IP = val(f["addr"])
		e.Program = exe
		e.Outcome = val(f["res"])
		switch r.kind {
		case "USER_START":
			if e.Outcome == "success" {
				e.Kind = "session_start"
			}
		case "USER_END":
			if e.Outcome == "success" {
				e.Kind = "session_end"
			}
		case "USER_AUTH":
			if e.Outcome == "failed" {
				e.Kind = "login_failure"
			}
		case "USER_LOGIN":
			if e.Outcome == "success" {
				e.Kind = "login_success"
			} else if e.Outcome == "failed" {
				e.Kind = "login_failure"
			}
		}
		if e.Kind != "" {
			e.ID += ":" + e.Kind
			out = append(out, e)
		}
	}
	if hasExec && syscall != nil {
		f := syscall.fields
		e := base
		e.Kind = "exec"
		e.ID += ":exec"
		e.SessionID = sessionID(boot, val(f["ses"]))
		e.PID = processID(f["pid"], 1)
		e.PPID = processID(f["ppid"], 0)
		e.LoginUID = val(f["auid"])
		if e.SessionID == "" || e.LoginUID == "4294967295" || e.LoginUID == "-1" {
			return out
		}
		e.User = lookup(e.LoginUID)
		e.EffectiveUser = lookup(val(f["euid"]))
		e.Program = auditString(f["exe"])
		e.Outcome = val(f["success"])
		for n, cs := range chunks {
			keys := []int{}
			for k := range cs {
				keys = append(keys, k)
			}
			sort.Ints(keys)
			var b strings.Builder
			for _, k := range keys {
				b.WriteString(cs[k])
			}
			args[n] = b.String()
		}
		keys := []int{}
		for k := range args {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			e.Args = append(e.Args, args[k])
		}
		e.Args = model.Redact(e.Args)
		out = append(out, e)
	}
	return out
}

// Missing IDs stay unknown rather than being confused with kernel/namespace PID 0.
func processID(raw string, minimum int) *int {
	n, err := strconv.ParseInt(val(raw), 10, 32)
	if err != nil || n < int64(minimum) {
		return nil
	}
	value := int(n)
	return &value
}
