package main

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"sshlogger/internal/model"
	"strconv"
	"testing"
	"time"
)

func TestTerminationIdentity(t *testing.T) {
	for _, id := range []string{"old:42", "boot:4294967295", "boot:-1", "boot:01", "boot:1/../../self", "boot:"} {
		if _, err := terminationSession("boot", id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	if sid, err := terminationSession("boot", "boot:42"); err != nil || sid != "42" {
		t.Fatal(sid, err)
	}
	if err := terminateAuditSession("boot", model.Termination{SessionID: "boot:42", Expires: time.Now().Add(-time.Second).UnixMilli()}); err == nil {
		t.Fatal("executed expired request")
	}
}

func TestSignalOnlyMatchingPinnedProcess(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "123456")
	os.Mkdir(base, 0700)
	os.WriteFile(filepath.Join(base, "sessionid"), []byte("42\n"), 0600)
	opened, signaled, closed := 0, 0, 0
	open := func(pid int) (int, error) {
		opened++
		if pid != 123456 {
			t.Fatal(pid)
		}
		return 99, nil
	}
	signal := func(fd int) error {
		signaled++
		if fd != 99 {
			t.Fatal("signal used numeric PID")
		}
		return nil
	}
	closeFD := func(fd int) error { closed++; return nil }
	for _, name := range []string{"self", "1", "0", "-1"} {
		if _, err := signalSessionProcess(root, name, "42", open, signal, closeFD); err != nil {
			t.Fatal(err)
		}
	}
	if opened != 0 {
		t.Fatal("opened protected process")
	}
	if matched, err := signalSessionProcess(root, "123456", "7", open, signal, closeFD); err != nil || matched || signaled != 0 || closed != 1 {
		t.Fatal(matched, err, signaled, closed)
	}
	if matched, err := signalSessionProcess(root, "123456", "42", open, signal, closeFD); err != nil || !matched || signaled != 1 || closed != 2 {
		t.Fatal(matched, err, signaled, closed)
	}
	// A process that exited after it was pinned must never fall back to kill(pid).
	if matched, err := signalSessionProcess(root, "123456", "42", open, func(int) error { return unix.ESRCH }, closeFD); err != nil || matched {
		t.Fatal(matched, err)
	}
}

func TestPinnedSignalTerminatesChild(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	root := t.TempDir()
	name := strconv.Itoa(child.Process.Pid)
	base := filepath.Join(root, name)
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "sessionid"), []byte("42"), 0600); err != nil {
		t.Fatal(err)
	}
	matched, err := signalSessionProcess(root, name, "42", func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) }, func(fd int) error { return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) }, unix.Close)
	if err == unix.ENOSYS {
		t.Skip("kernel does not support pidfd")
	}
	if err != nil || !matched {
		t.Fatal(matched, err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("expected child to be killed")
	}
}
