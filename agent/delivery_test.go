package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sshlogger/internal/model"
	"testing"
)

func TestDeliveryFailureKeepsQueueAndTokenRotation(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if e := os.WriteFile(tokenPath, []byte("old-token"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := openSpool(filepath.Join(dir, "spool.db"), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	if e = s.commit(checkpoint{}, []model.Event{{ID: "a", Kind: "exec"}}); e != nil {
		t.Fatal(e)
	}
	events, _, _ := s.batch()
	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer new-token" {
			t.Error("token file was not reloaded")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	if e = send(context.Background(), srv.Client(), srv.URL, tokenPath, model.Batch{Events: events}); e == nil {
		t.Fatal("expected delivery error")
	}
	_, n, _ := s.batch()
	if n != 1 {
		t.Fatal("unacknowledged event lost")
	}
	os.WriteFile(tokenPath, []byte("new-token"), 0600)
	if e = send(context.Background(), srv.Client(), srv.URL, tokenPath, model.Batch{Events: events}); e != nil {
		t.Fatal(e)
	}
	if e = s.ack(events); e != nil {
		t.Fatal(e)
	}
	_, n, _ = s.batch()
	if n != 0 {
		t.Fatal("ack failed")
	}
}
