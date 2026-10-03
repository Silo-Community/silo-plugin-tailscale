package tailscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

func validateHost(info *runtimehost.HostInfo) error {
	if info == nil || info.IngressToken == "" || info.Listener("api") == nil {
		return &PublicError{"host does not supply the network access contract"}
	}
	if info.HostRole != "api" && info.HostRole != "proxy" || info.HostRole == "proxy" && info.NodeID <= 0 {
		return &PublicError{"invalid host role or node identity"}
	}
	ports, names := map[int]bool{}, map[string]bool{}
	for _, l := range info.Listeners {
		if l.Name != "api" && l.Name != "jellyfin" && l.Name != "abs" || info.HostRole == "proxy" && l.Name != "api" {
			return &PublicError{"unsupported host listener"}
		}
		addr, err := netip.ParseAddrPort(l.Address)
		if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
			return &PublicError{"host listener must use a loopback IP and port"}
		}
		port := listenerPort(l)
		if port < 1 || port > 65535 || ports[port] || names[l.Name] {
			return &PublicError{"duplicate or invalid overlay listener port or name"}
		}
		ports[port], names[l.Name] = true, true
	}
	return nil
}

func listenerPort(l runtimehost.HostListener) int {
	if l.DefaultPort != 0 {
		return l.DefaultPort
	}
	switch l.Name {
	case "jellyfin":
		return 8096
	case "abs":
		return 13378
	default:
		return 443
	}
}

// discoveryRedirectPort is the plain HTTP port that redirects to the API
// origin, so clients on the tailnet can find the server as "http://<name>/".
const discoveryRedirectPort = 80

// offersDiscoveryRedirect reports whether this node answers on
// discoveryRedirectPort: only the API host, whose name people type or clients
// guess, and only when no Silo listener uses that port itself.
func offersDiscoveryRedirect(info *runtimehost.HostInfo) bool {
	if info.HostRole != "api" {
		return false
	}
	for _, l := range info.Listeners {
		if listenerPort(l) == discoveryRedirectPort {
			return false
		}
	}
	return true
}

func connectedStatus(info *runtimehost.HostInfo, st *ipnstate.Status) (*pluginv1.NetworkAccessStatus, error) {
	if st.Self == nil || st.CurrentTailnet == nil || !st.CurrentTailnet.MagicDNSEnabled {
		return nil, &PublicError{"enable MagicDNS in the Tailscale admin console"}
	}
	hostname := strings.TrimSuffix(st.Self.DNSName, ".")
	if hostname == "" || !slices.Contains(st.CertDomains, hostname) {
		return nil, &PublicError{"enable HTTPS certificates in the Tailscale admin console"}
	}
	s := &pluginv1.NetworkAccessStatus{State: "connected", Hostname: hostname}
	for _, ip := range st.TailscaleIPs {
		s.Addresses = append(s.Addresses, ip.String())
	}
	for _, l := range info.Listeners {
		origin := "https://" + hostname
		if port := listenerPort(l); port != 443 {
			origin = fmt.Sprintf("%s:%d", origin, port)
		}
		s.Listeners = append(s.Listeners, &pluginv1.NetworkAccessListener{Name: l.Name, Origin: origin})
		if l.Name == "api" {
			s.Origin = origin
		}
	}
	return s, nil
}

// overlay exposes the narrow tsnet surface used by the connection lifecycle
// and by sign-in (identitySource). Keeping transport construction here
// permits deterministic failure-path tests.
type overlay interface {
	identitySource
	Start() error
	Close() error
	Status(context.Context) (*ipnstate.Status, error)
	CertPair(context.Context, string) ([]byte, []byte, error)
	Listen(context.Context, string) (net.Listener, error)
	ListenTLS(context.Context, string, *tls.Config) (net.Listener, error)
	Watch(context.Context) (notificationWatcher, error)
}

type notificationWatcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

type tsnetOverlay struct {
	*tsnet.Server
	client *local.Client
}

func (s *tsnetOverlay) Start() error {
	if err := s.Server.Start(); err != nil {
		return err
	}
	var err error
	s.client, err = s.LocalClient()
	return err
}

// ListenTLS listens on the tailnet only. Up clears any Serve or Funnel
// configuration an earlier release left behind, so a node that had Funnel on
// stops answering publicly at the first start of this one.
func (s *tsnetOverlay) ListenTLS(ctx context.Context, address string, config *tls.Config) (net.Listener, error) {
	listener, err := s.Listen(ctx, address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

// Listen opens a plain TCP listener on the tailnet only.
func (s *tsnetOverlay) Listen(ctx context.Context, address string) (net.Listener, error) {
	if _, err := s.Server.Up(ctx); err != nil {
		return nil, err
	}
	return s.Server.Listen("tcp", address)
}

func (s *tsnetOverlay) Status(ctx context.Context) (*ipnstate.Status, error) {
	return s.client.StatusWithoutPeers(ctx)
}
func (s *tsnetOverlay) PeerStatus(ctx context.Context) (*ipnstate.Status, error) {
	return s.client.Status(ctx)
}
func (s *tsnetOverlay) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	return s.client.WhoIs(ctx, addr)
}
func (s *tsnetOverlay) ControlURL() string {
	if s.Server.ControlURL != "" {
		return s.Server.ControlURL
	}
	return ipn.DefaultControlURL
}
func (s *tsnetOverlay) CertPair(ctx context.Context, hostname string) ([]byte, []byte, error) {
	return s.client.CertPair(ctx, hostname)
}
func (s *tsnetOverlay) Watch(ctx context.Context) (notificationWatcher, error) {
	return s.client.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialHealthState|ipn.NotifyNoPrivateKeys)
}

// Run is the production overlay runner. identity receives the overlay while
// it is connected and serving, and nil otherwise, for sign-in lookups.
func Run(ctx context.Context, host Host, config Config, publish func(*pluginv1.NetworkAccessStatus), identity func(identitySource)) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	return runOverlay(ctx, host, config, publish, identity, func(info *runtimehost.HostInfo) overlay {
		return &tsnetOverlay{Server: &tsnet.Server{Hostname: Hostname(config, info), Store: StateStore{host}, NoLocalState: true,
			AuthKey: config.AuthKey, AdvertiseTags: config.Tags, UserLogf: func(string, ...any) {}, Logf: func(string, ...any) {}}}
	}, ticker.C)
}

func runOverlay(ctx context.Context, host Host, config Config, publish func(*pluginv1.NetworkAccessStatus), identity func(identitySource), newOverlay func(*runtimehost.HostInfo) overlay, ticks <-chan time.Time) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	identity = withdrawOnCancel(ctx, identity)
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	info, err := host.GetHostInfo(call)
	cancel()
	if err != nil {
		return &PublicError{"cannot read host listeners; reconnect to retry"}
	}
	if err := validateHost(info); err != nil {
		return err
	}
	srv := newOverlay(info)
	if err := srv.Start(); err != nil {
		return &PublicError{"cannot start tsnet; check encrypted state storage and retry"}
	}
	// Close is legal only after Start completes. It interrupts active network
	// operations and listeners on cancellation without deleting the identity.
	// Sign-in stops reading the node before it closes, so it answers "not
	// connected" instead of calling a closing LocalClient.
	closed := make(chan struct{})
	go func() { <-ctx.Done(); identity(nil); _ = srv.Close(); close(closed) }()
	defer func() { stop(); <-closed }()
	watcher, err := srv.Watch(ctx)
	if err != nil {
		return &PublicError{"cannot monitor tsnet; reconnect to retry"}
	}
	watchDone := make(chan struct{})
	changes := make(chan ipn.Notify)
	watchErrors := make(chan error, 1)
	go func() {
		defer close(watchDone)
		for {
			notification, err := watcher.Next()
			if err != nil {
				watchErrors <- err
				return
			}
			select {
			case changes <- notification:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { stop(); _ = watcher.Close(); <-watchDone }()
	loginError := false
	failures := make(chan error, len(info.Listeners))
	var servers []serving
	// Sign-in reads the node only while it is serving, so closing the
	// listeners withdraws it, including on a rename whose new certificate is
	// not issued yet.
	closeServers := func() {
		identity(nil)
		for _, s := range servers {
			s.close()
		}
		servers = nil
	}
	defer closeServers()
	lastHostname := ""
	var retryTimer *time.Timer
	var retryWake <-chan time.Time
	retryDelay := 15 * time.Second
	clearRetry := func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
		retryWake = nil
	}
	defer clearRetry()
	for {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := srv.Status(call)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return &PublicError{"cannot read tsnet status; reconnect to retry"}
		}
		if st.BackendState != "Running" || len(st.TailscaleIPs) == 0 {
			clearRetry()
			retryDelay = 15 * time.Second
			closeServers()
			s := &pluginv1.NetworkAccessStatus{State: "connecting"}
			if loginError {
				s.State, s.Error = "error", "Tailscale enrollment failed; check the auth key and network connectivity"
			}
			if st.AuthURL != "" {
				s.State, s.AuthUrl, s.Error = "awaiting_authorization", st.AuthURL, ""
			}
			if st.BackendState == "NeedsMachineAuth" {
				s.State, s.Error = "awaiting_authorization", ""
			}
			publish(s)
		} else {
			loginError = false
			s, err := connectedStatus(info, st)
			if err != nil {
				return err
			}
			if len(servers) != 0 && s.Hostname != lastHostname {
				closeServers()
			}
			if len(servers) == 0 {
				if retryWake != nil {
					goto waitForChange
				}
				// Enrollment is complete; discard the auth URL while HTTPS
				// issuance and listener setup are still in progress.
				publish(&pluginv1.NetworkAccessStatus{State: "connecting", Hostname: s.Hostname, Addresses: s.Addresses})
				call, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_, _, certErr := srv.CertPair(call, s.Hostname)
				cancel()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if certErr != nil {
					delay := certificateRetryDelay(certErr, retryDelay)
					publish(&pluginv1.NetworkAccessStatus{State: "error", Hostname: s.Hostname, Addresses: s.Addresses,
						Error: fmt.Sprintf("%s. Joined tailnet; HTTPS is not ready. Retrying in %s.", certificateError(certErr).Error(), delay.Round(time.Second))})
					retryTimer = time.NewTimer(delay)
					retryWake = retryTimer.C
					retryDelay = min(retryDelay*2, 5*time.Minute)
					goto waitForChange
				}
				retryDelay = 15 * time.Second
				for _, l := range info.Listeners {
					tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certificateFor(ctx, srv, s.Hostname)}
					ln, err := srv.ListenTLS(ctx, fmt.Sprintf(":%d", listenerPort(l)), tlsConfig)
					if err != nil {
						return &PublicError{"cannot open all overlay listeners; reconnect to retry"}
					}
					servers = append(servers, serve(ctx, ln, nil, l.Address, info.IngressToken, failures))
				}
				// Discovery is a convenience: a node that cannot open port
				// 80 still serves every listener, so its failures are ignored.
				if offersDiscoveryRedirect(info) {
					if ln, err := srv.Listen(ctx, fmt.Sprintf(":%d", discoveryRedirectPort)); err == nil {
						servers = append(servers, serveHandler(ctx, ln, nil, discoveryRedirect(s.Origin), nil))
					}
				}
				lastHostname = s.Hostname
			}
			identity(srv)
			publish(s)
		}
	waitForChange:
		select {
		case <-retryWake:
			retryWake = nil
		case <-ctx.Done():
			return ctx.Err()
		case <-failures:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return &PublicError{"overlay listener stopped; reconnect to retry"}
		case notification := <-changes:
			if notification.ErrMessage != nil {
				loginError = true
			}
			if notification.Health != nil {
				warning := notification.Health.Warnings[health.LoginStateWarnable.Code]
				loginError = warning.Args[health.ArgError] != ""
			}
		case <-watchErrors:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return &PublicError{"tsnet status monitoring stopped; reconnect to retry"}
		case <-ticks:
		}
	}
}

// withdrawOnCancel wraps identity so nothing is published once ctx is done.
// Shutdown withdraws the node before closing it, and a loop iteration racing
// the cancellation must not publish it again.
func withdrawOnCancel(ctx context.Context, identity func(identitySource)) func(identitySource) {
	var mu sync.Mutex
	return func(source identitySource) {
		mu.Lock()
		defer mu.Unlock()
		if source != nil && ctx.Err() != nil {
			return
		}
		identity(source)
	}
}

// certificateFor restricts issuance to this node and cancels certificate work
// with either the TLS handshake or the provider. The upstream GetCertificate
// helper starts from Background, allowing work to outlive a closed connection.
func certificateFor(ctx context.Context, node overlay, hostname string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), hostname) {
			return nil, &PublicError{"unexpected TLS server name"}
		}
		call, cancel := context.WithTimeout(hello.Context(), 10*time.Second)
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		defer cancel()
		certPEM, keyPEM, err := node.CertPair(call, hostname)
		if err != nil {
			return nil, &PublicError{"HTTPS certificate unavailable"}
		}
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, &PublicError{"invalid HTTPS certificate"}
		}
		return &certificate, nil
	}
}

// certificateError preserves actionable categories without exposing ACME
// challenge values, account URLs, authentication URLs, or private keys.
func certificateError(err error) error {
	message := "HTTPS certificate issuance failed; check tailnet HTTPS settings"
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		message = "HTTPS certificate issuance timed out; check DNS and certificate authority connectivity"
	default:
		detail := strings.ToLower(err.Error())
		switch {
		case strings.Contains(detail, "rate limit"), strings.Contains(detail, "ratelimited"), strings.Contains(detail, "429"):
			message = "HTTPS certificate issuance is rate limited; wait for the certificate authority retry window"
		case strings.Contains(detail, "encrypted overlay state"):
			message = "HTTPS certificate storage failed; check the plugin's encrypted instance storage"
		case strings.Contains(detail, "no tailscalevarroot"):
			message = "HTTPS certificate storage is unavailable; the custom state store was not selected"
		case strings.Contains(detail, "setdns"):
			message = "HTTPS certificate DNS challenge failed; check Tailscale control-plane connectivity and tailnet permissions"
		case strings.Contains(detail, "acme.register"), strings.Contains(detail, "acme.getreg"):
			message = "HTTPS certificate account registration failed; check certificate authority connectivity"
		case strings.Contains(detail, "x509"):
			message = "HTTPS certificate authority verification failed; check system time and trusted CA certificates"
		case strings.Contains(detail, "order"), strings.Contains(detail, "authorization"):
			message = "HTTPS certificate validation failed; check tailnet DNS and HTTPS configuration"
		}
	}
	return &PublicError{message}
}

func certificateRetryDelay(err error, backoff time.Duration) time.Duration {
	if after, limited := local.RateLimitRetryAfter(err); limited && after > backoff {
		return after
	}
	return backoff
}
