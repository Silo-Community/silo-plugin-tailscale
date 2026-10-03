package tailscale

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

type watchResult struct {
	notification ipn.Notify
	err          error
}

type fakeWatcher struct {
	ctx    context.Context
	events chan watchResult
	done   chan struct{}
	once   sync.Once
}

func (w *fakeWatcher) Next() (ipn.Notify, error) {
	select {
	case event := <-w.events:
		return event.notification, event.err
	case <-w.done:
		return ipn.Notify{}, net.ErrClosed
	case <-w.ctx.Done():
		return ipn.Notify{}, w.ctx.Err()
	}
}

func (w *fakeWatcher) Close() error {
	w.once.Do(func() { close(w.done) })
	return nil
}

type fakeOverlay struct {
	mu           sync.Mutex
	current      *ipnstate.Status
	statusError  error
	startError   error
	watchError   error
	certificate  func(context.Context, string) ([]byte, []byte, error)
	failListenAt int
	failPlain    bool
	listeners    []net.Listener
	ports        []string
	plainPorts   []string
	plain        map[string]net.Listener
	closed       bool
	watcher      *fakeWatcher
}

func newFakeOverlay() *fakeOverlay {
	return &fakeOverlay{
		current: &ipnstate.Status{BackendState: "NeedsLogin", AuthURL: "https://login.example.test/private"},
		watcher: &fakeWatcher{events: make(chan watchResult, 8), done: make(chan struct{})},
		certificate: func(context.Context, string) ([]byte, []byte, error) {
			return []byte("certificate"), []byte("key"), nil
		},
	}
}

func (n *fakeOverlay) Start() error { return n.startError }
func (n *fakeOverlay) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	for _, listener := range n.listeners {
		_ = listener.Close()
	}
	return n.watcher.Close()
}
func (n *fakeOverlay) Status(context.Context) (*ipnstate.Status, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.current, n.statusError
}
func (n *fakeOverlay) CertPair(ctx context.Context, hostname string) ([]byte, []byte, error) {
	n.mu.Lock()
	certificate := n.certificate
	n.mu.Unlock()
	return certificate(ctx, hostname)
}
func (n *fakeOverlay) Watch(ctx context.Context) (notificationWatcher, error) {
	n.watcher.ctx = ctx
	return n.watcher, n.watchError
}
func (n *fakeOverlay) ListenTLS(_ context.Context, address string, _ *tls.Config) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ports = append(n.ports, address)
	if len(n.ports) == n.failListenAt {
		return nil, errors.New("private listener error")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		n.listeners = append(n.listeners, listener)
	}
	return listener, err
}
func (n *fakeOverlay) Listen(_ context.Context, address string) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.plainPorts = append(n.plainPorts, address)
	if n.failPlain {
		return nil, errors.New("private listener error")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		n.listeners = append(n.listeners, listener)
		if n.plain == nil {
			n.plain = map[string]net.Listener{}
		}
		n.plain[address] = listener
	}
	return listener, err
}
func (n *fakeOverlay) PeerStatus(ctx context.Context) (*ipnstate.Status, error) { return n.Status(ctx) }
func (n *fakeOverlay) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return nil, local.ErrPeerNotFound
}
func (n *fakeOverlay) ControlURL() string { return "https://controlplane.tailscale.com" }
func (n *fakeOverlay) changeStatus(st *ipnstate.Status) {
	n.mu.Lock()
	n.current = st
	n.mu.Unlock()
	n.watcher.events <- watchResult{}
}

func runningStatus(hostname string) *ipnstate.Status {
	return &ipnstate.Status{
		BackendState: "Running", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Self:           &ipnstate.PeerStatus{DNSName: hostname + "."},
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true}, CertDomains: []string{hostname},
	}
}

type listenerHost struct {
	*memoryHost
	info *runtimehost.HostInfo
}

func (h listenerHost) GetHostInfo(context.Context) (*runtimehost.HostInfo, error) { return h.info, nil }

type overlayRun struct {
	statuses chan *pluginv1.NetworkAccessStatus
	done     chan struct{}
	err      error
	cancel   context.CancelFunc
	// identity is what the runner last published for sign-in;
	// withdrawnAfterClose records that it was still published when node
	// closed.
	node                *fakeOverlay
	identityMu          sync.Mutex
	identity            identitySource
	withdrawnAfterClose bool
}

func (r *overlayRun) setIdentity(source identitySource) {
	r.identityMu.Lock()
	defer r.identityMu.Unlock()
	if source == nil && r.identity != nil {
		r.node.mu.Lock()
		r.withdrawnAfterClose = r.withdrawnAfterClose || r.node.closed
		r.node.mu.Unlock()
	}
	r.identity = source
}

func (r *overlayRun) currentIdentity() identitySource {
	r.identityMu.Lock()
	defer r.identityMu.Unlock()
	return r.identity
}

func startFakeOverlay(t *testing.T, node *fakeOverlay, allListeners bool) *overlayRun {
	return startConfiguredOverlay(t, node, allListeners, Config{})
}
func startConfiguredOverlay(t *testing.T, node *fakeOverlay, allListeners bool, config Config) *overlayRun {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	run := &overlayRun{statuses: make(chan *pluginv1.NetworkAccessStatus, 32), done: make(chan struct{}), cancel: cancel, node: node}
	h := newHost()
	info, _ := h.GetHostInfo(ctx)
	if allListeners {
		info.Listeners = append(info.Listeners,
			runtimehost.HostListener{Name: "jellyfin", Address: "127.0.0.1:8096"},
			runtimehost.HostListener{Name: "abs", Address: "127.0.0.1:13378"})
	}
	go func() {
		defer close(run.done)
		run.err = runOverlay(ctx, listenerHost{h, info}, config, func(s *pluginv1.NetworkAccessStatus) {
			select {
			case run.statuses <- s:
			case <-ctx.Done():
			}
		}, run.setIdentity, func(*runtimehost.HostInfo) overlay { return node }, nil)
	}()
	t.Cleanup(func() { cancel(); _ = run.wait(t) })
	return run
}

func (r *overlayRun) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(5 * time.Second):
		t.Fatal("overlay did not stop")
		return nil
	}
}
func (r *overlayRun) state(t *testing.T, wanted string) *pluginv1.NetworkAccessStatus {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case s := <-r.statuses:
			if s.State == wanted {
				return s
			}
		case <-r.done:
			t.Fatalf("overlay stopped before %s: %v", wanted, r.err)
		case <-deadline.C:
			t.Fatalf("no %s status", wanted)
		}
	}
}

func TestOverlayEnrollmentAndListenerRecovery(t *testing.T) {
	node := newFakeOverlay()
	run := startFakeOverlay(t, node, true)
	if s := run.state(t, "awaiting_authorization"); s.AuthUrl == "" || s.Origin != "" {
		t.Fatal(s)
	}
	node.changeStatus(runningStatus("silo.example.test"))
	if s := run.state(t, "connecting"); s.AuthUrl != "" || s.Origin != "" {
		t.Fatal("authorization URL survived enrollment")
	}
	if s := run.state(t, "connected"); len(s.Listeners) != 3 || s.Origin != "https://silo.example.test" {
		t.Fatal(s)
	}
	node.mu.Lock()
	firstListener := node.listeners[0]
	if strings.Join(node.ports, ",") != ":443,:8096,:13378" {
		t.Errorf("ports: %v", node.ports)
	}
	node.mu.Unlock()
	node.changeStatus(&ipnstate.Status{BackendState: "Starting"})
	if s := run.state(t, "connecting"); len(s.Listeners) != 0 || s.Origin != "" {
		t.Fatal("lost backend retained origins")
	}
	if _, err := firstListener.Accept(); err == nil {
		t.Fatal("lost backend retained listener")
	}
	node.changeStatus(runningStatus("renamed.example.test"))
	if s := run.state(t, "connected"); s.Hostname != "renamed.example.test" {
		t.Fatal("stale hostname")
	}
	run.cancel()
	if err := run.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if !node.closed || len(node.ports) != 6 {
		t.Fatal("overlay lifecycle was not completed")
	}
}

func TestOverlayEnrollmentFailureIsSafeAndCanRecover(t *testing.T) {
	node := newFakeOverlay()
	node.current.AuthURL = ""
	run := startFakeOverlay(t, node, false)
	run.state(t, "connecting")
	secret := "rejected tskey-auth-private at https://login.example.test/private"
	node.watcher.events <- watchResult{notification: ipn.Notify{ErrMessage: &secret}}
	s := run.state(t, "error")
	if strings.Contains(s.Error, "private") || s.AuthUrl != "" || s.Origin != "" {
		t.Fatal("upstream error escaped")
	}
	node.watcher.events <- watchResult{notification: ipn.Notify{Health: &health.State{}}}
	run.state(t, "connecting")
	node.changeStatus(runningStatus("silo.example.test"))
	run.state(t, "connected")
}

func TestOverlayFailureClosesPartialListeners(t *testing.T) {
	for _, failure := range []string{"start", "watch", "second-listener", "status", "watch-stream"} {
		t.Run(failure, func(t *testing.T) {
			node := newFakeOverlay()
			node.current = runningStatus("silo.example.test")
			secret := errors.New("private failure with credentials")
			switch failure {
			case "start":
				node.startError = secret
			case "watch":
				node.watchError = secret
			case "second-listener":
				node.failListenAt = 2
			case "status":
				node.statusError = secret
			case "watch-stream":
				node.watcher.events <- watchResult{err: secret}
			}
			run := startFakeOverlay(t, node, true)
			err := run.wait(t)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe error: %v", err)
			}
			node.mu.Lock()
			defer node.mu.Unlock()
			if failure != "start" && !node.closed {
				t.Fatal("overlay left running")
			}
			for _, listener := range node.listeners {
				if _, err := listener.Accept(); err == nil {
					t.Fatal("partial listener left open")
				}
			}
		})
	}
}

func TestCertificateLookupCanceledWithProviderOrHandshake(t *testing.T) {
	for _, cause := range []string{"provider", "handshake"} {
		t.Run(cause, func(t *testing.T) {
			node := newFakeOverlay()
			called := make(chan struct{})
			node.certificate = func(ctx context.Context, _ string) ([]byte, []byte, error) {
				close(called)
				<-ctx.Done()
				return nil, nil, ctx.Err()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			handshake, stopHandshake := context.WithCancel(t.Context())
			defer stopHandshake()
			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()
			server := tls.Server(serverConn, &tls.Config{GetCertificate: certificateFor(ctx, node, "silo.example.test"), MinVersion: tls.VersionTLS12})
			client := tls.Client(clientConn, &tls.Config{ServerName: "SILO.EXAMPLE.TEST", InsecureSkipVerify: true}) // DNS names are case-insensitive; this test cancels before verification.
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(handshake) }()
			go func() { _ = client.HandshakeContext(handshake) }()
			select {
			case <-called:
			case <-time.After(5 * time.Second):
				t.Fatal("no certificate lookup")
			}
			if cause == "provider" {
				cancel()
			} else {
				stopHandshake()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled handshake succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("certificate work survived cancellation")
			}
		})
	}
}

func TestCertificateRejectsOtherNamesBeforeIssuance(t *testing.T) {
	node := newFakeOverlay()
	node.certificate = func(context.Context, string) ([]byte, []byte, error) {
		t.Fatal("issued certificate for another name")
		return nil, nil, nil
	}
	getter := certificateFor(t.Context(), node, "silo.example.test")
	for _, name := range []string{"", "other.example.test", "../../escape"} {
		if _, err := getter(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("accepted SNI %q", name)
		}
	}
}

func TestCertificateErrorsDoNotExposePrivateDetails(t *testing.T) {
	cases := []struct {
		cause error
		want  string
	}{
		{context.DeadlineExceeded, "timed out"},
		{errors.New("429 rate limited secret-token"), "rate limited"},
		{errors.New("SetDNS private-challenge secret-token"), "DNS challenge failed"},
		{errors.New("cannot save encrypted overlay state secret-token"), "storage failed"},
		{errors.New("acme.Register secret-token"), "registration failed"},
		{errors.New("x509 secret-token"), "verification failed"},
		{errors.New("private error secret-token"), "issuance failed"},
	}
	for _, test := range cases {
		got := certificateError(test.cause).Error()
		if !strings.Contains(got, test.want) || strings.Contains(got, "secret-token") {
			t.Fatalf("unsafe or unhelpful error: %s", got)
		}
	}
}

func TestCertificateRetryRemainsResponsiveToReauthorization(t *testing.T) {
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	node.certificate = func(context.Context, string) ([]byte, []byte, error) {
		return nil, nil, errors.New("private challenge")
	}
	run := startFakeOverlay(t, node, false)
	failed := run.state(t, "error")
	if failed.Hostname != "silo.example.test" || failed.Origin != "" || strings.Contains(failed.Error, "private") {
		t.Fatal(failed)
	}
	node.changeStatus(&ipnstate.Status{BackendState: "NeedsLogin", AuthURL: "https://login.example.test/reauth"})
	run.state(t, "awaiting_authorization")
	run.cancel()
	if err := run.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCertificateAutomaticallyRecovers(t *testing.T) {
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	attempts := 0
	node.certificate = func(context.Context, string) ([]byte, []byte, error) {
		attempts++
		if attempts == 1 {
			return nil, nil, errors.New("transient failure")
		}
		return []byte("cert"), []byte("key"), nil
	}
	run := startFakeOverlay(t, node, false)
	run.state(t, "error")
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case s := <-run.statuses:
			if s.State == "connected" {
				if s.Origin != "https://silo.example.test" {
					t.Fatal(s)
				}
				return
			}
		case <-deadline.C:
			t.Fatal("certificate retry did not recover")
		}
	}
}

// Sign-in reads the overlay only while it is connected and serving.
func TestOverlayPublishesIdentityOnlyWhileServing(t *testing.T) {
	node := newFakeOverlay()
	run := startFakeOverlay(t, node, true)
	run.state(t, "awaiting_authorization")
	if run.currentIdentity() != nil {
		t.Fatal("identity published before the node joined")
	}
	node.changeStatus(runningStatus("silo.example.test"))
	run.state(t, "connected")
	if run.currentIdentity() != node {
		t.Fatal("connected overlay not published for sign-in")
	}
	node.mu.Lock()
	if len(node.ports) != 3 {
		node.mu.Unlock()
		t.Fatalf("listeners: %v", node.ports)
	}
	node.mu.Unlock()
	node.changeStatus(&ipnstate.Status{BackendState: "NeedsLogin"})
	run.state(t, "connecting")
	if run.currentIdentity() != nil {
		t.Fatal("identity still published after the node left the tailnet")
	}
	run.cancel()
	_ = run.wait(t)
	if run.currentIdentity() != nil {
		t.Fatal("identity still published after the overlay stopped")
	}
}

// On Disconnect, sign-in stops reading the node before it closes, so it
// answers "not connected" instead of calling a closing LocalClient.
func TestOverlayWithdrawsIdentityBeforeClosingTheNode(t *testing.T) {
	node := newFakeOverlay()
	run := startFakeOverlay(t, node, false)
	node.changeStatus(runningStatus("silo.example.test"))
	run.state(t, "connected")
	run.cancel()
	_ = run.wait(t)
	run.identityMu.Lock()
	defer run.identityMu.Unlock()
	if run.identity != nil || run.withdrawnAfterClose {
		t.Fatalf("identity = %v, withdrawn after close = %v; want withdrawn before the node closed", run.identity, run.withdrawnAfterClose)
	}
}

// A renamed node closes its listeners. Until the new name's certificate is
// issued nothing serves, so sign-in must not answer for the node.
func TestOverlayWithdrawsIdentityWhileRenamedNodeHasNoCertificate(t *testing.T) {
	node := newFakeOverlay()
	run := startFakeOverlay(t, node, false)
	node.changeStatus(runningStatus("silo.example.test"))
	run.state(t, "connected")
	node.mu.Lock()
	node.certificate = func(context.Context, string) ([]byte, []byte, error) { return nil, nil, errors.New("issuance failed") }
	node.mu.Unlock()
	node.changeStatus(runningStatus("renamed.example.test"))
	run.state(t, "error")
	if run.currentIdentity() != nil {
		t.Fatal("identity still published while the renamed node serves nothing")
	}
}

// redirectClient does not follow redirects, gives up quickly, and does not
// leave connections in the shared transport's pool.
func redirectClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func discoveryListener(t *testing.T, node *fakeOverlay) net.Listener {
	t.Helper()
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.plain[":80"]
}

func redirectLocation(t *testing.T, listener net.Listener, path string) string {
	t.Helper()
	response, err := redirectClient(t).Get("http://" + listener.Addr().String() + path)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", response.StatusCode)
	}
	return response.Header.Get("Location")
}

func TestOverlayRedirectsPlainHTTPToTheAPIOrigin(t *testing.T) {
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	run := startConfiguredOverlay(t, node, true, Config{Discovery: true})
	run.state(t, "connected")
	node.mu.Lock()
	ports := strings.Join(node.ports, ",")
	node.mu.Unlock()
	if ports != ":443,:8096,:13378" {
		t.Fatalf("TLS ports %s", ports)
	}
	redirect := discoveryListener(t, node)
	if redirect == nil {
		t.Fatal("no discovery listener on :80")
	}
	if got := redirectLocation(t, redirect, "/api/v2/system/identity?x=1"); got != "https://silo.example.test/api/v2/system/identity?x=1" {
		t.Fatalf("Location = %q", got)
	}
}

func TestOverlayDiscoveryListenerFollowsTheNode(t *testing.T) {
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	run := startConfiguredOverlay(t, node, false, Config{Discovery: true})
	run.state(t, "connected")
	first := discoveryListener(t, node)

	node.changeStatus(&ipnstate.Status{BackendState: "Starting"})
	run.state(t, "connecting")
	if _, err := first.Accept(); err == nil {
		t.Fatal("discovery listener survived backend loss")
	}

	node.changeStatus(runningStatus("renamed.example.test"))
	if s := run.state(t, "connected"); s.Hostname != "renamed.example.test" {
		t.Fatal(s)
	}
	renamed := discoveryListener(t, node)
	if renamed == nil || renamed == first {
		t.Fatal("discovery listener was not reopened")
	}
	if got := redirectLocation(t, renamed, "/"); got != "https://renamed.example.test/" {
		t.Fatalf("Location after rename = %q", got)
	}
}

func TestOverlayRetriesTheDiscoveryListenerAndServesMeanwhile(t *testing.T) {
	previous := discoveryRetryDelay
	discoveryRetryDelay = 0
	t.Cleanup(func() { discoveryRetryDelay = previous })
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	node.failPlain = true
	run := startConfiguredOverlay(t, node, false, Config{Discovery: true})
	if s := run.state(t, "connected"); s.Origin != "https://silo.example.test" {
		t.Fatal(s)
	}
	node.mu.Lock()
	attempted := strings.Join(node.plainPorts, ",")
	node.failPlain = false
	node.mu.Unlock()
	if attempted != ":80" {
		t.Fatalf("discovery listen attempts = %q, want :80", attempted)
	}
	// Any later pass of the loop opens it again.
	node.changeStatus(runningStatus("silo.example.test"))
	run.state(t, "connected")
	if discoveryListener(t, node) == nil {
		t.Fatal("discovery listener was not retried")
	}
}

func TestOverlayDiscoveryOffKeepsPort80Closed(t *testing.T) {
	node := newFakeOverlay()
	node.current = runningStatus("silo.example.test")
	run := startConfiguredOverlay(t, node, false, Config{Discovery: false})
	run.state(t, "connected")
	node.mu.Lock()
	defer node.mu.Unlock()
	if len(node.plainPorts) != 0 {
		t.Fatalf("discovery off still listened on %v", node.plainPorts)
	}
}

func TestOffersDiscoveryRedirect(t *testing.T) {
	api := runtimehost.HostListener{Name: "api", Address: "127.0.0.1:8080", DefaultPort: 443}
	on, off := Config{Discovery: true}, Config{}
	for _, tc := range []struct {
		name   string
		config Config
		info   *runtimehost.HostInfo
		want   bool
	}{
		{"api host", on, &runtimehost.HostInfo{HostRole: "api", Listeners: []runtimehost.HostListener{api}}, true},
		{"discovery off", off, &runtimehost.HostInfo{HostRole: "api", Listeners: []runtimehost.HostListener{api}}, false},
		{"proxy host", on, &runtimehost.HostInfo{HostRole: "proxy", NodeID: 1, Listeners: []runtimehost.HostListener{api}}, false},
		{"listener on 80", on, &runtimehost.HostInfo{HostRole: "api", Listeners: []runtimehost.HostListener{
			{Name: "api", Address: "127.0.0.1:8080", DefaultPort: 80}}}, false},
	} {
		if got := offersDiscoveryRedirect(tc.config, tc.info); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
