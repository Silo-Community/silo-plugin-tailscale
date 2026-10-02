package tailscale

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"tailscale.com/ipn"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// Exercise the real userspace stack against a local control server. No real
// tailnet, account, auth key, or external certificate authority is contacted.
func TestTSNetStoresIdentityWithoutLocalFiles(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{DERPMap: integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"), MagicDNSDomain: "example.test", DNSConfig: &tailcfg.DNSConfig{Proxied: true}}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	h := newHost()
	store := StateStore{h}
	stateDir := t.TempDir()
	newServer := func() *tsnet.Server {
		return &tsnet.Server{Hostname: "silo-test", ControlURL: control.HTTPTestServer.URL,
			Dir: stateDir, Store: store, NoLocalState: true, UserLogf: logger.Discard, Logf: logger.Discard}
	}
	s := newServer()
	s.AuthKey = "test-key"
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	first, err := s.Up(ctx)
	if err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.SetServeConfig(ctx, &ipn.ServeConfig{AllowFunnel: map[ipn.HostPort]bool{"silo.example.test:443": true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if first.Self == nil || first.Self.PublicKey.IsZero() {
		t.Fatal("initial node identity missing")
	}
	if identity, err := store.ReadState("_machinekey"); err != nil || len(identity) == 0 {
		t.Fatal("machine identity missing from host store")
	}
	// Reuse only the host-backed state. A fresh tsnet instance must reconnect
	// as the same node without an enrollment key or any local state files.
	restarted := newServer()
	adapter := &tsnetOverlay{Server: restarted}
	if err := adapter.Start(); err != nil {
		t.Fatal(err)
	}
	listener, err := adapter.ListenTLS(ctx, ":443", &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		_ = restarted.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	serveConfig, err := adapter.client.GetServeConfig(ctx)
	if err != nil || serveConfig != nil && len(serveConfig.AllowFunnel) != 0 {
		_ = restarted.Close()
		t.Fatal("private restart retained Funnel configuration", err)
	}
	second, err := adapter.Status(ctx)
	if err != nil {
		_ = restarted.Close()
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if second.Self == nil || second.Self.PublicKey != first.Self.PublicKey || second.Self.ID != first.Self.ID {
		t.Fatal("restart changed the stored node identity")
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("tsnet wrote local files: %v", entries)
	}
	t.Run("production", func(t *testing.T) {
		testProductionStateStore(t, control.HTTPTestServer.URL)
	})
}

func testProductionStateStore(t *testing.T, controlURL string) {
	t.Helper()
	// A normal executable is essential: tsnet skips its logger in test
	// binaries, which would hide a regression in the NoLocalState guard.
	probe := filepath.Join(t.TempDir(), "stateprobe")
	buildCtx, cancelBuild := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", probe, "./testdata/stateprobe")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production state probe: %v\n%s", err, output)
	}
	root := t.TempDir()
	stateDir, workingDir := filepath.Join(root, "state"), filepath.Join(root, "working")
	for _, directory := range []string{stateDir, workingDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, probe, controlURL, stateDir)
	command.Dir = workingDir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("production state probe: %v\n%s", err, output)
	}
	// NoLocalState also clears the internal root path. If logtail is enabled
	// accidentally, its files would land in the working directory instead.
	for _, directory := range []string{stateDir, workingDir} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("production tsnet wrote local files in %s: %v", filepath.Base(directory), entries)
		}
	}
}
