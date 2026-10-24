package tailscale

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/ipn"
)

type memoryHost struct {
	mu                  sync.Mutex
	values              map[string][]byte
	failRead, failWrite bool
	reports             chan *pluginv1.NetworkAccessStatus
}

func newHost() *memoryHost {
	return &memoryHost{values: map[string][]byte{}, reports: make(chan *pluginv1.NetworkAccessStatus, 100)}
}
func (h *memoryHost) GetHostInfo(context.Context) (*runtimehost.HostInfo, error) {
	return &runtimehost.HostInfo{HostRole: "api", IngressToken: "test-token", Listeners: []runtimehost.HostListener{{Name: "api", Address: "127.0.0.1:8080", DefaultPort: 443}}}, nil
}
func (h *memoryHost) ReadInstanceState(_ context.Context, key string) ([]byte, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failRead {
		return nil, false, errors.New("secret upstream failure")
	}
	b, ok := h.values[key]
	return append([]byte{}, b...), ok, nil
}
func (h *memoryHost) WriteInstanceState(_ context.Context, key string, b []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failWrite {
		return errors.New("secret upstream failure")
	}
	h.values[key] = append([]byte{}, b...)
	return nil
}
func (h *memoryHost) ReportNetworkAccessStatus(ctx context.Context, s *pluginv1.NetworkAccessStatus) error {
	select {
	case h.reports <- s:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func waitState(t *testing.T, h *memoryHost, state string) *pluginv1.NetworkAccessStatus {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case s := <-h.reports:
			if s.State == state {
				return s
			}
		case <-timer.C:
			t.Fatalf("no %s status", state)
			return nil
		}
	}
}

func TestRestoreAndDisconnectPreserveIdentity(t *testing.T) {
	h := newHost()
	h.values[desiredKey] = []byte("1")
	h.values["node"] = []byte("identity")
	started := make(chan struct{}, 1)
	runner := func(ctx context.Context, _ Host, _ Config, publish func(*pluginv1.NetworkAccessStatus)) error {
		started <- struct{}{}
		publish(&pluginv1.NetworkAccessStatus{State: "awaiting_authorization", AuthUrl: "https://login.example.test/secret"})
		<-ctx.Done()
		// A late result must never resurrect a disconnected provider.
		publish(&pluginv1.NetworkAccessStatus{State: "connected", Origin: "https://stale.invalid"})
		return ctx.Err()
	}
	p := New(h, Config{}, runner)
	defer p.Close()
	if err := p.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("restart did not reconnect")
	}
	s := waitState(t, h, "awaiting_authorization")
	if s.AuthUrl == "" || !s.DesiredConnected {
		t.Fatal(s)
	}
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	s, err := p.Disconnect(t.Context(), nil)
	if err != nil || s.State != "disconnected" || s.DesiredConnected || s.AuthUrl != "" || s.Origin != "" {
		t.Fatalf("%v %v", s, err)
	}
	waitState(t, h, "disconnected")
	if b, _, _ := h.ReadInstanceState(t.Context(), desiredKey); string(b) != "0" {
		t.Fatal("intent not persisted")
	}
	if b, _, _ := h.ReadInstanceState(t.Context(), "node"); string(b) != "identity" {
		t.Fatal("identity lost")
	}
}

func TestPersistenceFailuresDoNotChangeIntent(t *testing.T) {
	h := newHost()
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		<-ctx.Done()
		return ctx.Err()
	})
	defer p.Close()
	h.failRead = true
	if err := p.Restore(t.Context()); err == nil {
		t.Fatal("ignored failed state read")
	}
	h.failRead = false
	h.failWrite = true
	if _, err := p.Connect(t.Context(), nil); err == nil {
		t.Fatal("ignored failed save")
	}
	if p.snapshot().DesiredConnected {
		t.Fatal("changed intent despite failed write")
	}
	h.failWrite = false
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.failWrite = true
	h.mu.Unlock()
	if _, err := p.Disconnect(t.Context(), nil); err == nil {
		t.Fatal("ignored failed disconnect save")
	}
	if !p.snapshot().DesiredConnected {
		t.Fatal("changed intent despite failed write")
	}
}

func TestCanceledConnectRPCDoesNotCancelEnrollment(t *testing.T) {
	h := newHost()
	started := make(chan context.Context, 1)
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	})
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	if _, err := p.Connect(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	runCtx := <-started
	if runCtx.Err() != nil {
		t.Fatal("enrollment tied to RPC lifetime")
	}
	p.Close()
	if b, _, _ := h.ReadInstanceState(t.Context(), desiredKey); string(b) != "1" {
		t.Fatal("process stop cleared operator intent")
	}
}

func TestUnknownErrorsDoNotExposeSecrets(t *testing.T) {
	h := newHost()
	p := New(h, Config{}, func(context.Context, Host, Config, func(*pluginv1.NetworkAccessStatus)) error {
		return errors.New("tskey-auth-secret https://login.example.test/secret")
	})
	defer p.Close()
	_, _ = p.Connect(t.Context(), nil)
	s := waitState(t, h, "error")
	if s.Error != "overlay stopped unexpectedly; reconnect to retry" || !s.DesiredConnected {
		t.Fatal(s)
	}
	copy := p.snapshot()
	copy.Error = "changed"
	if p.snapshot().Error == "changed" {
		t.Fatal("status shares mutable data")
	}
}

func TestRestoreIsIdempotent(t *testing.T) {
	h := newHost()
	h.values[desiredKey] = []byte("1")
	started := make(chan context.Context, 2)
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		started <- ctx
		select {
		case <-ctx.Done():
		case <-t.Context().Done():
		}
		return ctx.Err()
	})
	defer p.Close()
	if err := p.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := <-started
	if err := p.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if first.Err() == nil {
		t.Fatal("restoring twice abandoned the original runner")
	}
	select {
	case <-started:
		t.Fatal("restoring twice started another runner")
	default:
	}
}

func TestCloseIsTerminalAndIdempotent(t *testing.T) {
	h := newHost()
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		<-ctx.Done()
		return ctx.Err()
	})
	defer p.Close()
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	p.Close()
	p.Close()
	for name, operation := range map[string]func() error{
		"restore":    func() error { return p.Restore(t.Context()) },
		"connect":    func() error { _, err := p.Connect(t.Context(), nil); return err },
		"disconnect": func() error { _, err := p.Disconnect(t.Context(), nil); return err },
		"status":     func() error { _, err := p.GetStatus(t.Context(), nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("closed provider accepted operation: %v", err)
			}
		})
	}
	if b, _, _ := h.ReadInstanceState(t.Context(), desiredKey); string(b) != "1" {
		t.Fatal("operation after Close changed saved intent")
	}
}

func TestGetStatusRejectsRetiredProviderDuringShutdown(t *testing.T) {
	h := newHost()
	stopping := make(chan struct{})
	release := make(chan struct{})
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, publish func(*pluginv1.NetworkAccessStatus)) error {
		publish(&pluginv1.NetworkAccessStatus{State: "connected", Origin: "https://silo.example.test"})
		<-ctx.Done()
		close(stopping)
		<-release
		return ctx.Err()
	})
	defer p.Close()
	defer close(release)
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	waitState(t, h, "connected")
	go p.Close()
	<-stopping
	result := make(chan error, 1)
	go func() {
		s, err := p.GetStatus(t.Context(), nil)
		if s != nil {
			result <- errors.New("retired provider exposed stale status")
			return
		}
		result <- err
	}()
	select {
	case err := <-result:
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("retired provider returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetStatus blocked behind provider shutdown")
	}
}

type blockedWriteHost struct {
	*memoryHost
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockedWriteHost) WriteInstanceState(ctx context.Context, key string, value []byte) error {
	h.once.Do(func() { close(h.entered) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-h.release:
		return h.memoryHost.WriteInstanceState(ctx, key, value)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestLifecycleWaitHonorsCancellation(t *testing.T) {
	h := &blockedWriteHost{memoryHost: newHost(), entered: make(chan struct{}), release: make(chan struct{})}
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		<-ctx.Done()
		return ctx.Err()
	})
	defer p.Close()
	var release sync.Once
	defer release.Do(func() { close(h.release) })
	connected := make(chan error, 1)
	go func() { _, err := p.Connect(t.Context(), nil); connected <- err }()
	<-h.entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, operation := range map[string]func() error{
		"restore":    func() error { return p.Restore(ctx) },
		"connect":    func() error { _, err := p.Connect(ctx, nil); return err },
		"disconnect": func() error { _, err := p.Disconnect(ctx, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			go func() { result <- operation() }()
			select {
			case err := <-result:
				if status.Code(err) != codes.Canceled {
					t.Fatalf("canceled operation returned %v", err)
				}
			case <-time.After(5 * time.Second):
				release.Do(func() { close(h.release) })
				t.Fatal("canceled operation remained queued behind state persistence")
			}
		})
	}
	release.Do(func() { close(h.release) })
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
}

func TestCanceledStateWriteDoesNotStartRunner(t *testing.T) {
	h := &blockedWriteHost{memoryHost: newHost(), entered: make(chan struct{}), release: make(chan struct{})}
	started := make(chan struct{}, 1)
	p := New(h, Config{}, func(context.Context, Host, Config, func(*pluginv1.NetworkAccessStatus)) error {
		started <- struct{}{}
		return nil
	})
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.Connect(ctx, nil); result <- err }()
	<-h.entered
	cancel()
	if err := <-result; status.Code(err) != codes.Canceled {
		t.Fatalf("canceled state write returned %v", err)
	}
	p.Close()
	select {
	case <-started:
		t.Fatal("canceled state write started the runner")
	default:
	}
}

func TestConnectRetriesActiveErrorRun(t *testing.T) {
	h := newHost()
	started := make(chan context.Context, 2)
	p := New(h, Config{}, func(ctx context.Context, _ Host, _ Config, publish func(*pluginv1.NetworkAccessStatus)) error {
		started <- ctx
		publish(&pluginv1.NetworkAccessStatus{State: "error", Error: "enrollment failed"})
		<-ctx.Done()
		return ctx.Err()
	})
	defer p.Close()
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	first := <-started
	waitState(t, h, "error")
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-started:
		if first.Err() == nil || second.Err() != nil {
			t.Fatal("retry did not retire the failed runner before starting its replacement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not retry an active runner in the error state")
	}
}

type blockedReportHost struct {
	*memoryHost
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

func (h *blockedReportHost) ReportNetworkAccessStatus(ctx context.Context, _ *pluginv1.NetworkAccessStatus) error {
	close(h.entered)
	<-ctx.Done()
	close(h.canceled)
	<-h.release
	return ctx.Err()
}

func TestCloseWaitsForStatusReporter(t *testing.T) {
	h := &blockedReportHost{memoryHost: newHost(), entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	p := New(h, Config{}, nil)
	defer p.Close()
	defer close(h.release)
	if err := p.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-h.entered
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	<-h.canceled
	select {
	case <-closed:
		t.Fatal("Close returned with an active status report")
	default:
	}
}

func TestStoreRoundTripAndIsolation(t *testing.T) {
	a, b := StateStore{newHost()}, StateStore{newHost()}
	if _, err := a.ReadState("missing"); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatal(err)
	}
	for _, key := range []ipn.StateKey{"_machinekey", "profile-test", "acme-account.key.pem", "silo.example.test.key", "silo.example.test.crt"} {
		if err := a.WriteState(key, []byte("secret")); err != nil {
			t.Fatal(err)
		}
		got, err := a.ReadState(key)
		if err != nil || string(got) != "secret" {
			t.Fatalf("%s: %v", key, err)
		}
		if _, err := b.ReadState(key); !errors.Is(err, ipn.ErrStateNotExist) {
			t.Fatal("cross-instance state leak")
		}
	}
	if err := a.WriteState("empty", []byte{}); err != nil {
		t.Fatal(err)
	}
	if got, err := a.ReadState("empty"); err != nil || len(got) != 0 {
		t.Fatal("empty value confused with missing")
	}
}

func TestTsnetVersionReadsLinkedModule(t *testing.T) {
	// The adapted build replaces tailscale.com but keeps the go.mod version.
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "tailscale.com/other", Version: "v9.9.9"},
		{Path: "tailscale.com", Version: "v1.102.4", Replace: &debug.Module{Path: "./.build/tailscale", Version: "(devel)"}},
	}}
	if got := tsnetVersion(info, true); got != "tsnet 1.102.4" {
		t.Fatalf("tsnetVersion = %q, want %q", got, "tsnet 1.102.4")
	}
	if got := tsnetVersion(nil, false); got != "tsnet" {
		t.Fatalf("tsnetVersion without build info = %q, want %q", got, "tsnet")
	}
}
