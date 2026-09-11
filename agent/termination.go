package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sshlogger/internal/model"
)

func terminationAvailable() bool {
	if os.Geteuid() != 0 {
		return false
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	return unix.PidfdSendSignal(fd, 0, nil, 0) == nil
}

func terminationSession(boot, id string) (string, error) {
	prefix := boot + ":"
	if boot == "" || !strings.HasPrefix(id, prefix) {
		return "", fmt.Errorf("다른 부팅의 세션입니다.")
	}
	sid := strings.TrimPrefix(id, prefix)
	n, err := strconv.ParseUint(sid, 10, 32)
	if err != nil || n == 4294967295 || strconv.FormatUint(n, 10) != sid {
		return "", fmt.Errorf("잘못된 세션 ID입니다.")
	}
	return sid, nil
}

// Pin the process before checking its audit session, so PID reuse cannot send
// a signal to a different process. Never fall back to a numeric PID kill.
func signalSessionProcess(root, name, sid string, open func(int) (int, error), signal func(int) error, closeFD func(int) error) (bool, error) {
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return false, nil
	}
	fd, err := open(pid)
	if err == unix.ESRCH {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer closeFD(fd)
	b, err := os.ReadFile(filepath.Join(root, name, "sessionid"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(b)) != sid {
		return false, nil
	}
	err = signal(fd)
	if err == unix.ESRCH {
		return false, nil
	}
	return err == nil, err
}

func terminateAuditSession(boot string, c model.Termination) error {
	if time.Now().UnixMilli() >= c.Expires {
		return fmt.Errorf("종료 요청이 만료되었습니다.")
	}
	sid, err := terminationSession(boot, c.SessionID)
	if err != nil {
		return err
	}
	own, err := os.ReadFile("/proc/self/sessionid")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(own)) == sid {
		return fmt.Errorf("에이전트 자신의 세션은 종료할 수 없습니다.")
	}
	// Repeat scans to catch children created while the first scan was running.
	for pass := 0; pass < 3; pass++ {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return err
		}
		for _, entry := range entries {
			_, err = signalSessionProcess("/proc", entry.Name(), sid,
				func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
				func(fd int) error { return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) }, unix.Close)
			if err != nil {
				return fmt.Errorf("세션 종료 실패: %v", err)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A successful signal is not proof that all processes have exited.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		b, err := os.ReadFile(filepath.Join(base, "sessionid"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(b)) != sid {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(base, "stat"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 || end+2 >= len(stat) || (stat[end+2] != 'Z' && stat[end+2] != 'X') {
			return fmt.Errorf("세션 프로세스가 아직 남아 있습니다.")
		}
	}
	return nil
}
