package tailscale

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// Sign-in against the real userspace stack and a local control server: a
// second node dials the Silo node over the tailnet, and the Silo node names
// the dialer's owner and reads the Silo grant the policy gives them. No real
// tailnet or account is contacted.
func TestSignInIdentifiesTailnetPeers(t *testing.T) {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{DERPMap: integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"), MagicDNSDomain: "example.test", DNSConfig: &tailcfg.DNSConfig{Proxied: true}}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{CapSilo: {`{"role":"admin"}`}})

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	newNode := func(name string) *tsnet.Server {
		node := &tsnet.Server{Hostname: name, ControlURL: control.HTTPTestServer.URL, Dir: t.TempDir(), AuthKey: "test-key",
			UserLogf: logger.Discard, Logf: logger.Discard}
		if _, err := node.Up(ctx); err != nil {
			_ = node.Close()
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = node.Close() })
		return node
	}
	silo, tv := newNode("silo"), newNode("living-room-tv")
	adapter := &tsnetOverlay{Server: silo}
	if err := adapter.Start(); err != nil {
		t.Fatal(err)
	}

	listener, err := silo.Listen("tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Addr, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn.RemoteAddr()
		_ = conn.Close()
	}()
	siloIPv4, _ := silo.TailscaleIPs()
	conn, err := tv.Dial(ctx, "tcp", net.JoinHostPort(siloIPv4.String(), "80"))
	if err != nil {
		t.Fatalf("dial the Silo node over the tailnet: %v", err)
	}
	_ = conn.Close()
	var remote net.Addr
	select {
	case remote = <-accepted:
	case <-ctx.Done():
		t.Fatal("the Silo node never accepted the connection")
	}
	peer, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		t.Fatalf("remote address %q: %v", remote, err)
	}
	tvIPv4, _ := tv.TailscaleIPs()
	if peer.Addr() != tvIPv4 {
		t.Fatalf("connection came from %v, want the TV's %v", peer.Addr(), tvIPv4)
	}

	p := &Provider{config: Config{SignInAccess: SignInPolicy}}
	p.setIdentity(adapter)
	// The grant reaches the node with a map update; wait for it.
	var signedIn *pluginv1.AuthenticateResponse
	for {
		signedIn, err = p.AuthenticatePeer(ctx, &pluginv1.AuthenticatePeerRequest{PeerAddress: peer.Addr().String()})
		if err != nil {
			t.Fatal(err)
		}
		if signedIn.GetManagedRole() == pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN || ctx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if signedIn.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED || signedIn.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("sign-in = %+v, want the TV's owner as admin", signedIn)
	}
	if !strings.HasPrefix(signedIn.GetExternalSubject(), subjectPrefix(adapter.ControlURL())) || signedIn.GetIssuer() != control.HTTPTestServer.URL {
		t.Fatalf("subject %q / issuer %q not scoped to the test control plane", signedIn.GetExternalSubject(), signedIn.GetIssuer())
	}

	checked, err := p.CheckAccount(ctx, &pluginv1.CheckAccountRequest{ExternalSubject: signedIn.GetExternalSubject()})
	if err != nil {
		t.Fatal(err)
	}
	if checked.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE || checked.GetAccount().GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("re-check = %+v, want active admin", checked)
	}

	// A person with no device the Silo node can see is not on the tailnet as
	// far as sign-in is concerned; the Silo node itself does not count.
	self, err := adapter.Status(ctx)
	if err != nil || self.Self == nil {
		t.Fatal("cannot read the Silo node's own status", err)
	}
	ownSubject := subjectPrefix(adapter.ControlURL()) + strconv.FormatInt(int64(self.Self.UserID), 10)
	if ownSubject != signedIn.GetExternalSubject() {
		got, err := p.CheckAccount(ctx, &pluginv1.CheckAccountRequest{ExternalSubject: ownSubject})
		if err != nil || got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
			t.Fatalf("person whose only node is the Silo node = %v, %v", got.GetStatus(), err)
		}
	}
}
