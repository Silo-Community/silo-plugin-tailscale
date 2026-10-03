package tailscale

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NewProxy replaces all client-supplied forwarding metadata. Rewrite runs
// after hop-by-hop headers are removed, so Connection cannot strip our token.
func NewProxy(address, token string) (*httputil.ReverseProxy, *http.Transport) {
	transport := &http.Transport{
		Proxy:        nil,
		DialContext:  (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	p := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Silo listener unavailable", http.StatusBadGateway)
		},
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: address})
			r.Out.Host = r.In.Host
			r.Out.Header.Del("Forwarded")
			r.Out.Header.Del("X-Forwarded-Host")
			r.Out.Header.Del("X-Real-IP")
			peer, _, err := net.SplitHostPort(r.In.RemoteAddr)
			if err != nil {
				peer = r.In.RemoteAddr
			}
			r.Out.Header.Set("X-Forwarded-For", peer)
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			r.Out.Header.Set("X-Silo-Ingress-Token", token)
			// Every connection comes from a tailnet peer (the node listens on
			// the tailnet only), so Silo may ask who it is (AuthenticatePeer),
			// unless another proxy relayed the request.
			r.Out.Header.Del("X-Silo-Ingress-Peer")
			if addr, err := netip.ParseAddr(peer); err == nil && !relayed(r.In.Header) {
				r.Out.Header.Set("X-Silo-Ingress-Peer", addr.String())
			}
		},
	}
	return p, transport
}

// relayHeaders mark a request that another proxy forwarded: a reverse proxy
// or Tailscale Serve/Funnel on a tailnet device, pointed at this node. The
// connection then comes from the relay's device, so its owner is not the
// person making the request. A relay that adds none of them (a plain TCP
// forwarder) cannot be told apart; such a device must be tagged, and tagged
// devices are refused.
var relayHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Real-IP", "Via", "CF-Connecting-IP", "True-Client-IP"}

// relayed reports whether header carries a relay's forwarding metadata,
// including Tailscale Serve's identity headers (Tailscale-*).
func relayed(header http.Header) bool {
	for _, name := range relayHeaders {
		if header.Values(name) != nil {
			return true
		}
	}
	for name := range header {
		if strings.HasPrefix(name, "Tailscale-") {
			return true
		}
	}
	return false
}

// Track hijacked WebSocket connections too: http.Server.Close alone leaves
// them alive, which would let a disconnected provider continue proxying.
type connections struct {
	mu  sync.Mutex
	all map[net.Conn]struct{}
}

type trackedConn struct {
	net.Conn
	owner *connections
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.all, c)
	c.owner.mu.Unlock()
	return err
}

type trackedListener struct {
	net.Listener
	owner *connections
}

func (l trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{conn, l.owner}
	l.owner.mu.Lock()
	l.owner.all[tracked] = struct{}{}
	l.owner.mu.Unlock()
	return tracked, nil
}
func (c *connections) close() {
	c.mu.Lock()
	all := c.all
	c.all = make(map[net.Conn]struct{})
	c.mu.Unlock()
	for conn := range all {
		_ = conn.Close()
	}
}

type serving struct {
	server      *http.Server
	transport   *http.Transport
	connections *connections
	done        <-chan struct{}
}

func serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config, address, token string, failures chan<- error) serving {
	proxy, transport := NewProxy(address, token)
	s := serveHandler(ctx, listener, tlsConfig, proxy, failures)
	s.transport = transport
	return s
}

// serveHandler serves handler on listener until close. A nil failures
// channel makes the server's failure invisible to the connection lifecycle.
func serveHandler(ctx context.Context, listener net.Listener, tlsConfig *tls.Config, handler http.Handler, failures chan<- error) serving {
	connections := &connections{all: make(map[net.Conn]struct{})}
	listener = trackedListener{listener, connections}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			select {
			case failures <- err:
			default:
			}
		}
	}()
	return serving{server: server, connections: connections, done: done}
}
func (s serving) close() {
	_ = s.server.Close()
	// Close may run before Serve registers the listener. Wait for Serve's
	// deferred listener close before allowing this port to be opened again.
	<-s.done
	s.connections.close()
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

// discoveryRedirect answers plain HTTP on the overlay with a redirect to the
// API's HTTPS origin. A client that knows only the short MagicDNS name
// ("http://silo/") cannot use HTTPS at that name, because the certificate
// covers the full tailnet name; the redirect hands it that name. It never
// proxies, so no request reaches Silo without TLS. The redirect is temporary
// because the node can be renamed.
func discoveryRedirect(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "use HTTPS", http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, origin+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
}
