package tailscale

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type closeObservedListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *closeObservedListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func TestCloseBeforeServeStartsClosesListener(t *testing.T) {
	// A single processor exercises shutdown before the Serve goroutine starts.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := &closeObservedListener{Listener: ln, closed: make(chan struct{})}
		t.Cleanup(func() { _ = listener.Close() })
		s := serve(t.Context(), listener, nil, "127.0.0.1:1", "token", make(chan error, 1))
		s.close()
		select {
		case <-listener.closed:
		default:
			t.Fatal("close returned before the listener closed")
		}
	}
}

func TestProxyPreservesPlaybackAndReplacesSpoofedHeaders(t *testing.T) {
	got := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(context.Background())
		w.Header().Set("Content-Range", "bytes 2-4/6")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "cde")
	}))
	defer upstream.Close()
	proxy, transport := NewProxy(strings.TrimPrefix(upstream.URL, "http://"), "host-token")
	defer transport.CloseIdleConnections()
	front := httptest.NewServer(proxy)
	defer front.Close()
	req, _ := http.NewRequest("GET", front.URL+"/media/a%2Fb?token=opaque%2Bvalue&x=1&x=2", nil)
	req.Host = "silo.example.test:8096"
	req.Header.Set("Range", "bytes=2-4")
	req.Header.Set("Authorization", "Bearer playback-token")
	req.Header["X-Silo-Ingress-Token"] = []string{"spoof-one", "spoof-two"}
	req.Header.Set("Connection", "X-Silo-Ingress-Token, X-Forwarded-Proto")
	req.Header.Set("Forwarded", "for=spoof;proto=http")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-For", "spoof")
	req.Header.Set("X-Forwarded-Host", "evil.invalid")
	req.Header.Set("X-Real-IP", "spoof")
	req.Header["X-Silo-Ingress-Peer"] = []string{"100.64.0.66", "100.64.0.67"}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 206 || string(b) != "cde" || resp.Header.Get("Content-Range") != "bytes 2-4/6" {
		t.Fatal("range response changed")
	}
	r := <-got
	if r.Host != req.Host || r.RequestURI != "/media/a%2Fb?token=opaque%2Bvalue&x=1&x=2" || r.Header.Get("Range") != "bytes=2-4" || r.Header.Get("Authorization") != "Bearer playback-token" {
		t.Fatal("request changed")
	}
	if r.Header.Get("X-Silo-Ingress-Token") != "host-token" || len(r.Header.Values("X-Silo-Ingress-Token")) != 1 || r.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("ingress metadata spoofed")
	}
	if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Real-IP") != "" {
		t.Fatal("forwarded identity spoofed")
	}
	// A request that carries forwarding headers came through a relay, so it
	// names no peer, and a client's own peer claim never survives.
	if peers := r.Header.Values("X-Silo-Ingress-Peer"); peers != nil {
		t.Fatalf("ingress peer = %v, want none for a relayed request", peers)
	}
}

// The peer Silo asks about is the connection's, never a client's claim, and
// only when no relay forwarded the request.
func TestProxyNamesThePeerOnlyForDirectRequests(t *testing.T) {
	got := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(context.Background())
	}))
	defer upstream.Close()
	proxy, transport := NewProxy(strings.TrimPrefix(upstream.URL, "http://"), "host-token")
	defer transport.CloseIdleConnections()
	front := httptest.NewServer(proxy)
	defer front.Close()
	for _, tc := range []struct {
		name   string
		header string
		want   []string
	}{
		{"direct", "", []string{"127.0.0.1"}},
		{"direct with a forged peer", "X-Silo-Ingress-Peer", []string{"127.0.0.1"}},
		{"reverse proxy", "X-Forwarded-For", nil},
		{"standard forwarding", "Forwarded", nil},
		{"nginx", "X-Real-IP", nil},
		{"HTTP proxy", "Via", nil},
		{"Cloudflare tunnel", "CF-Connecting-IP", nil},
		{"Tailscale Serve", "Tailscale-User-Login", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", front.URL+"/api/v2/auth/providers", nil)
			if tc.header != "" {
				req.Header.Set(tc.header, "100.64.0.66")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if peers := (<-got).Header.Values("X-Silo-Ingress-Peer"); !slices.Equal(peers, tc.want) {
				t.Fatalf("ingress peer = %v, want %v", peers, tc.want)
			}
		})
	}
}

func TestWebSocketUpgradeAndDisconnectClosesTunnel(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) { testWebSocketDisconnect(t, nil, nil) })
	t.Run("HTTPS", func(t *testing.T) {
		serverTLS, clientTLS := proxyTestTLS(t)
		testWebSocketDisconnect(t, serverTLS, clientTLS)
	})
}

func proxyTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	serverTLS := fixture.TLS.Clone()
	serverTLS.MinVersion = tls.VersionTLS12
	clientTLS := fixture.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return serverTLS, clientTLS
}

func testWebSocketDisconnect(t *testing.T, serverTLS, clientTLS *tls.Config) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, conn)
	}))
	defer upstream.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t.Context(), ln, serverTLS, strings.TrimPrefix(upstream.URL, "http://"), "token", make(chan error, 1))
	defer s.close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if clientTLS != nil {
		clientTLS.ServerName = "127.0.0.1"
		tlsConn := tls.Client(conn, clientTLS)
		if err := tlsConn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		conn = tlsConn
	}
	_, _ = fmt.Fprintf(conn, "GET /events HTTP/1.1\r\nHost: silo.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	_, _ = conn.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil || string(b) != "ping" {
		t.Fatal("tunnel does not pass data")
	}
	s.close()
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("disconnected tunnel still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("tunnel not closed before deadline")
	}
}

func TestTLSDisconnectCancelsStreamingUpstream(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamCanceled)
	}))
	defer upstream.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := proxyTestTLS(t)
	s := serve(t.Context(), ln, serverTLS, strings.TrimPrefix(upstream.URL, "http://"), "token", make(chan error, 1))
	defer s.close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + ln.Addr().String() + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	reader := bufio.NewReader(resp.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("stream start = %q, %v", line, err)
	}
	s.close()
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("disconnected stream is still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("stream did not close before the client timeout")
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("disconnect left the upstream request running")
	}
}

func TestProxyResponseHeaderTimeoutIsSanitized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()
	proxy, transport := NewProxy(strings.TrimPrefix(upstream.URL, "http://"), "private-ingress-token")
	transport.ResponseHeaderTimeout = 20 * time.Millisecond
	defer transport.CloseIdleConnections()
	front := httptest.NewServer(proxy)
	defer front.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(front.URL + "/?token=private-playback-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway || string(body) != "Silo listener unavailable\n" {
		t.Fatalf("upstream timeout response = %d %q", resp.StatusCode, body)
	}
}

func TestProxyFlushesEvents(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	proxy, transport := NewProxy(strings.TrimPrefix(upstream.URL, "http://"), "token")
	defer transport.CloseIdleConnections()
	front := httptest.NewServer(proxy)
	defer front.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", front.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: ready\n" {
		t.Fatalf("event buffered: %q %v", line, err)
	}
}
