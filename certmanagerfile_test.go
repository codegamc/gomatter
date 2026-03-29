package gomatter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileCertManagerStoresFilesInConfiguredDirectory(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "certs")
	cm := NewFileCertManager(0x1234, FileCertManagerConfig{Path: certDir})

	if err := cm.BootstrapCa(); err != nil {
		t.Fatalf("BootstrapCa() error = %v", err)
	}
	if err := cm.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cm.CreateUser(0x42); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	for _, name := range []string{
		"ca-private.pem",
		"ca-public.pem",
		"ca-cert.pem",
		"66-private.pem",
		"66-public.pem",
		"66-cert.pem",
	} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
}

func TestFileCertManagerLoadReturnsMissingCAError(t *testing.T) {
	cm := NewFileCertManager(0x1234, FileCertManagerConfig{Path: t.TempDir()})

	err := cm.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want missing CA error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want wrapped os.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "ca-private.pem") {
		t.Fatalf("Load() error = %v, want ca-private.pem in message", err)
	}
}

func TestFileCertManagerCreateUserReturnsSigningError(t *testing.T) {
	cm := NewFileCertManager(0x1234, FileCertManagerConfig{Path: t.TempDir()})

	err := cm.CreateUser(0x42)
	if err == nil {
		t.Fatal("CreateUser() error = nil, want signing error")
	}
	if !strings.Contains(err.Error(), "must be loaded") {
		t.Fatalf("CreateUser() error = %v, want CA load failure", err)
	}
}

func TestNewFileCertManagerDefaultsToPemDirectory(t *testing.T) {
	cm := NewFileCertManager(0x1234, FileCertManagerConfig{})

	if cm.path != "pem" {
		t.Fatalf("path = %q, want %q", cm.path, "pem")
	}
}
