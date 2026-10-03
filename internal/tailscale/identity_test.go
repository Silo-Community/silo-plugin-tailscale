package tailscale

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// fakeTailnet answers WhoIs and the peer list from fixed tables.
type fakeTailnet struct {
	whois      map[string]*apitype.WhoIsResponse
	status     *ipnstate.Status
	whoisErr   error
	statusErr  error
	whoisCalls int
}

func (f *fakeTailnet) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.whoisCalls++
	if f.whoisErr != nil {
		return nil, f.whoisErr
	}
	if who, ok := f.whois[addr]; ok {
		return who, nil
	}
	return nil, local.ErrPeerNotFound
}
func (f *fakeTailnet) ControlURL() string { return "https://controlplane.tailscale.com" }

// PeerStatus answers the fixed peer list, or without one, every device WhoIs
// knows.
func (f *fakeTailnet) PeerStatus(context.Context) (*ipnstate.Status, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.status != nil {
		return f.status, nil
	}
	var peers []*ipnstate.PeerStatus
	for addr, who := range f.whois {
		if who.Node != nil && who.UserProfile != nil {
			peers = append(peers, peer(*who.UserProfile, addr, who.Node.Tags...))
		}
	}
	return peerList(peers...), nil
}

var (
	alice = tailcfg.UserProfile{ID: 101, LoginName: "alice@example.com", DisplayName: "Alice Example", ProfilePicURL: "https://img.example.com/a.png"}
	bob   = tailcfg.UserProfile{ID: 202, LoginName: "bob@github", DisplayName: "Bob"}
)

func grants(values ...string) tailcfg.PeerCapMap {
	raw := make([]tailcfg.RawMessage, 0, len(values))
	for _, v := range values {
		raw = append(raw, tailcfg.RawMessage(v))
	}
	return tailcfg.PeerCapMap{CapSilo: raw}
}

func device(profile tailcfg.UserProfile, caps tailcfg.PeerCapMap, tags ...string) *apitype.WhoIsResponse {
	p := profile
	return &apitype.WhoIsResponse{Node: &tailcfg.Node{User: profile.ID, Tags: tags}, UserProfile: &p, CapMap: caps}
}

func signInProvider(source identitySource, access string) *Provider {
	p := &Provider{config: Config{SignInAccess: access}}
	p.setIdentity(source)
	return p
}

func authenticate(t *testing.T, p *Provider, peer string) *pluginv1.AuthenticateResponse {
	t.Helper()
	response, err := p.AuthenticatePeer(t.Context(), &pluginv1.AuthenticatePeerRequest{PeerAddress: peer})
	if err != nil {
		t.Fatalf("AuthenticatePeer(%s) = %v", peer, err)
	}
	return response
}

func TestAuthenticatePeerIdentifiesTheDeviceOwner(t *testing.T) {
	tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{
		"100.64.0.7":        device(alice, nil),
		"100.64.0.8":        device(bob, nil),
		"fd7a:115c:a1e0::9": device(alice, nil),
	}}
	p := signInProvider(tailnet, SignInAnyone)

	got := authenticate(t, p, "100.64.0.7")
	if got.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED || got.GetExternalSubject() != "controlplane.tailscale.com|101" ||
		got.GetIssuer() != "https://controlplane.tailscale.com" || got.GetUsername() != "alice@example.com" ||
		got.GetEmail() != "alice@example.com" || got.GetDisplayName() != "Alice Example" || got.GetPictureUrl() != "https://img.example.com/a.png" {
		t.Fatalf("response = %+v", got)
	}
	if got.EmailVerified != nil {
		t.Fatal("email_verified must stay unset so Silo never matches accounts by it")
	}
	if got.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Fatalf("role without a grant = %v, want unspecified", got.GetManagedRole())
	}
	// A GitHub login is not an email address.
	if got := authenticate(t, p, "100.64.0.8"); got.GetEmail() != "" || got.GetUsername() != "bob@github" {
		t.Fatalf("GitHub login = %+v", got)
	}
	// The same person from another device has the same subject.
	if got := authenticate(t, p, "fd7a:115c:a1e0::9"); got.GetExternalSubject() != "controlplane.tailscale.com|101" {
		t.Fatalf("IPv6 device subject = %q", got.GetExternalSubject())
	}
}

// Sign-in answers the person's role, the highest any of their devices is
// granted, as re-checks do; otherwise signing in from a device with a
// narrower grant would flip the role at every sign-in and re-check.
func TestAuthenticatePeerAnswersThePersonsRole(t *testing.T) {
	tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{
		"100.64.0.7": device(alice, grants(`{"role":"user"}`)),
		"100.64.0.8": device(alice, grants(`{"role":"admin"}`)),
	}}
	p := signInProvider(tailnet, SignInPolicy)
	signedIn := authenticate(t, p, "100.64.0.7")
	if signedIn.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Fatalf("sign-in role = %v, want admin from the person's other device", signedIn.GetManagedRole())
	}
	if checked := check(t, p, signedIn.GetExternalSubject()); checked.GetAccount().GetManagedRole() != signedIn.GetManagedRole() {
		t.Fatalf("re-check role %v differs from sign-in role %v", checked.GetAccount().GetManagedRole(), signedIn.GetManagedRole())
	}
	failing := &fakeTailnet{whois: tailnet.whois, statusErr: errors.New("local api down")}
	if got := authenticate(t, signInProvider(failing, SignInAnyone), "100.64.0.7"); got.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE {
		t.Fatalf("peer list unreadable = %+v", got)
	}
}

// An exit node carries traffic out of the tailnet, not into it, so its owner
// still signs in from it.
func TestAuthenticatePeerAllowsExitNodes(t *testing.T) {
	exitNode := device(alice, nil)
	exitNode.Node.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}).View()
	tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{"100.64.0.7": exitNode}}
	if got := authenticate(t, signInProvider(tailnet, SignInAnyone), "100.64.0.7"); got.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
		t.Fatalf("exit node = %+v, want signed in", got)
	}
}

// Sign-in reuses the requesting device's WhoIs for the person's role instead
// of asking again.
func TestAuthenticatePeerAsksWhoIsOncePerDevice(t *testing.T) {
	tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{
		"100.64.0.7": device(alice, grants(`{"role":"user"}`)),
		"100.64.0.8": device(alice, nil),
	}}
	authenticate(t, signInProvider(tailnet, SignInAnyone), "100.64.0.7")
	if tailnet.whoisCalls != 2 {
		t.Fatalf("WhoIs calls = %d, want 2 (one per device)", tailnet.whoisCalls)
	}
}

func TestAuthenticatePeerRefusals(t *testing.T) {
	expired := device(alice, nil)
	expired.Node.Expired = true
	router := device(alice, nil)
	router.Node.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	advertising := device(alice, nil)
	advertising.Node.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}).View()
	tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{
		"100.64.0.10": device(alice, nil, "tag:tv"),
		"100.64.0.11": {Node: &tailcfg.Node{}},
		"100.64.0.12": device(bob, nil),
		"100.64.0.13": expired,
		"100.64.0.14": router,
		"100.64.0.15": advertising,
	}}
	// The node knows the device, but its peer list has no device of the
	// person: CheckAccount would answer not found.
	unlisted := &fakeTailnet{whois: tailnet.whois, status: peerList(peer(alice, "100.64.0.20"))}
	for _, tc := range []struct {
		name   string
		p      *Provider
		peer   string
		denial pluginv1.AuthDenial
	}{
		{"not connected", signInProvider(nil, SignInAnyone), "100.64.0.12", pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
		{"tagged device", signInProvider(tailnet, SignInAnyone), "100.64.0.10", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"no user", signInProvider(tailnet, SignInAnyone), "100.64.0.11", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"unknown peer", signInProvider(tailnet, SignInAnyone), "100.64.0.99", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"not an address", signInProvider(tailnet, SignInAnyone), "laptop", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"policy mode without grant", signInProvider(tailnet, SignInPolicy), "100.64.0.12", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"whois failing", signInProvider(&fakeTailnet{whoisErr: errors.New("local api down")}, SignInAnyone), "100.64.0.12", pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE},
		{"expired device", signInProvider(tailnet, SignInAnyone), "100.64.0.13", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"subnet router", signInProvider(tailnet, SignInAnyone), "100.64.0.14", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"advertises routes", signInProvider(tailnet, SignInAnyone), "100.64.0.15", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
		{"person not in the peer list", signInProvider(unlisted, SignInAnyone), "100.64.0.12", pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := authenticate(t, tc.p, tc.peer)
			if got.GetDenial() != tc.denial || got.GetExternalSubject() != "" {
				t.Fatalf("response = %+v, want denial %v and no subject", got, tc.denial)
			}
		})
	}
}

func TestGrantsSetTheRoleAndPolicyModeAccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		caps    tailcfg.PeerCapMap
		role    pluginv1.AuthManagedRole
		granted bool
	}{
		{"no grant", nil, pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"admin", grants(`{"role":"admin"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN, true},
		{"user", grants(`{"role":"user"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER, true},
		{"empty value", grants(`{}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER, true},
		{"unknown role", grants(`{"role":"owner"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"misspelled role", grants(`{"role":"Admin"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"misspelled key", grants(`{"rol":"admin"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"null", grants(`null`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"not an object", grants(`["admin"]`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"trailing data", grants(`{} {}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"malformed only", grants(`not json`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false},
		{"malformed beside user", grants(`not json`, `{"role":"user"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER, true},
		{"highest wins", grants(`{"role":"user"}`, `{"role":"admin"}`, `{"role":"user"}`), pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role, granted := grantedRole(tc.caps)
			if role != tc.role || granted != tc.granted {
				t.Fatalf("grantedRole = %v, %v; want %v, %v", role, granted, tc.role, tc.granted)
			}
			tailnet := &fakeTailnet{whois: map[string]*apitype.WhoIsResponse{"100.64.0.7": device(alice, tc.caps)}}
			got := authenticate(t, signInProvider(tailnet, SignInPolicy), "100.64.0.7")
			if tc.granted != (got.GetDenial() == pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED) || tc.granted && got.GetManagedRole() != tc.role {
				t.Fatalf("policy mode response = %+v", got)
			}
		})
	}
}

// peer is one node in the node's peer list.
func peer(profile tailcfg.UserProfile, ip string, tags ...string) *ipnstate.PeerStatus {
	status := &ipnstate.PeerStatus{UserID: profile.ID, TailscaleIPs: []netip.Addr{netip.MustParseAddr(ip)}}
	if len(tags) > 0 {
		view := views.SliceOf(tags)
		status.Tags = &view
	}
	return status
}

func peerList(peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	status := &ipnstate.Status{BackendState: "Running", Peer: map[key.NodePublic]*ipnstate.PeerStatus{},
		User: map[tailcfg.UserID]tailcfg.UserProfile{alice.ID: alice, bob.ID: bob}}
	for _, p := range peers {
		status.Peer[key.NewNode().Public()] = p
	}
	return status
}

func check(t *testing.T, p *Provider, subject string) *pluginv1.CheckAccountResponse {
	t.Helper()
	response, err := p.CheckAccount(t.Context(), &pluginv1.CheckAccountRequest{ExternalSubject: subject})
	if err != nil {
		t.Fatalf("CheckAccount(%s) = %v", subject, err)
	}
	return response
}

func TestCheckAccountFollowsThePeerList(t *testing.T) {
	tailnet := &fakeTailnet{
		status: peerList(peer(alice, "100.64.0.7"), peer(alice, "100.64.0.8"), peer(bob, "100.64.0.9", "tag:tv")),
		whois: map[string]*apitype.WhoIsResponse{
			"100.64.0.7": device(alice, grants(`{"role":"user"}`)),
			"100.64.0.8": device(alice, grants(`{"role":"admin"}`)),
		},
	}
	p := signInProvider(tailnet, SignInAnyone)
	got := check(t, p, "controlplane.tailscale.com|101")
	if got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE ||
		got.GetAccount().GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN ||
		got.GetAccount().GetDisplayName() != "Alice Example" {
		t.Fatalf("active person = %+v, want active with the highest role across devices", got)
	}
	// A device whose key expired cannot reach the node and does not count.
	expired := peer(alice, "100.64.0.7")
	expired.Expired = true
	gone := &fakeTailnet{status: peerList(expired), whois: tailnet.whois}
	if got := check(t, signInProvider(gone, SignInAnyone), "controlplane.tailscale.com|101"); got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
		t.Fatalf("person with only an expired device = %v", got.GetStatus())
	}
	// Bob's only device is tagged: as a person he is gone from the tailnet.
	if got := check(t, p, "controlplane.tailscale.com|202"); got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
		t.Fatalf("person with only a tagged device = %v", got.GetStatus())
	}
	for _, subject := range []string{"controlplane.tailscale.com|303", "headscale.example.com|101", "controlplane.tailscale.com|x", "101"} {
		if got := check(t, p, subject); got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND {
			t.Fatalf("subject %q = %v, want not found", subject, got.GetStatus())
		}
	}
}

func TestCheckAccountPolicyModeAndOutages(t *testing.T) {
	tailnet := &fakeTailnet{
		status: peerList(peer(alice, "100.64.0.7")),
		whois:  map[string]*apitype.WhoIsResponse{"100.64.0.7": device(alice, nil)},
	}
	if got := check(t, signInProvider(tailnet, SignInPolicy), "controlplane.tailscale.com|101"); got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED {
		t.Fatalf("policy mode without a grant = %v", got.GetStatus())
	}
	if got := check(t, signInProvider(tailnet, SignInAnyone), "controlplane.tailscale.com|101"); got.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE ||
		got.GetAccount().GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Fatalf("default mode without a grant = %+v", got)
	}
	unavailable := pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE
	if got := check(t, signInProvider(nil, SignInAnyone), "controlplane.tailscale.com|101"); got.GetStatus() != unavailable {
		t.Fatalf("disconnected = %v", got.GetStatus())
	}
	stopped := &fakeTailnet{status: &ipnstate.Status{BackendState: "Starting"}}
	if got := check(t, signInProvider(stopped, SignInAnyone), "controlplane.tailscale.com|101"); got.GetStatus() != unavailable {
		t.Fatalf("node not running = %v", got.GetStatus())
	}
	failing := &fakeTailnet{status: peerList(peer(alice, "100.64.0.7")), whoisErr: errors.New("local api down")}
	if got := check(t, signInProvider(failing, SignInAnyone), "controlplane.tailscale.com|101"); got.GetStatus() != unavailable {
		t.Fatalf("WhoIs failing = %v", got.GetStatus())
	}
}

func TestAuthenticateRefusesPasswords(t *testing.T) {
	got, err := signInProvider(nil, SignInAnyone).Authenticate(t.Context(), &pluginv1.AuthenticateRequest{Username: "alice", Password: "pw"})
	if err != nil || got.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS || got.GetExternalSubject() != "" {
		t.Fatalf("Authenticate = %+v, %v", got, err)
	}
}
