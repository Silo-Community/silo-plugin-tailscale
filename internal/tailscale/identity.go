package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Sign-in with tailnet identity (Silo's "network" auth mode). Silo calls
// AuthenticatePeer with the peer address this plugin stamped on a request it
// proxied (X-Silo-Ingress-Peer), and CheckAccount to re-check an account
// later. Both answer from the running node: WhoIs for the peer, the peer list
// for the re-check. The tailnet policy decides access and role through the
// CapSilo app capability; see the README.

// CapSilo is the app capability a tailnet policy grants to let a person sign
// in to Silo and to set their Silo role. Each value is a JSON object such as
// {"role":"admin"} or {"role":"user"}.
const CapSilo tailcfg.PeerCapability = "siloserver.org/cap/silo"

// identitySource is the tsnet surface sign-in reads. The overlay runner
// publishes it while the node is connected and serving.
type identitySource interface {
	WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
	PeerStatus(context.Context) (*ipnstate.Status, error)
	ControlURL() string
}

func (p *Provider) setIdentity(source identitySource) {
	p.identityMu.Lock()
	p.identity = source
	p.identityMu.Unlock()
}

func (p *Provider) currentIdentity() identitySource {
	p.identityMu.RLock()
	defer p.identityMu.RUnlock()
	return p.identity
}

// AuthenticatePeer identifies the overlay peer of a request this plugin
// proxied: the person who owns the device, never a tagged device.
func (p *Provider) AuthenticatePeer(ctx context.Context, req *pluginv1.AuthenticatePeerRequest) (*pluginv1.AuthenticateResponse, error) {
	source := p.currentIdentity()
	if source == nil {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "tailnet is not connected"), nil
	}
	peer, err := netip.ParseAddr(req.GetPeerAddress())
	if err != nil {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "invalid peer address"), nil
	}
	who, err := source.WhoIs(ctx, peer.String())
	if errors.Is(err, local.ErrPeerNotFound) {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "unknown peer"), nil
	}
	if err != nil {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "cannot identify peer"), nil
	}
	if who == nil || who.Node == nil || who.UserProfile == nil || who.UserProfile.ID == 0 {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "peer has no user identity"), nil
	}
	if who.Node.IsTagged() {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "tagged device"), nil
	}
	if who.Node.Expired {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "device key expired"), nil
	}
	if p.config.RefuseSubnetRouters && routesForOthers(who.Node) {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "device routes traffic for other machines"), nil
	}
	role, granted := grantedRole(who.CapMap)
	if p.config.SignInAccess == SignInPolicy && !granted {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "no Silo grant"), nil
	}
	// The role is the person's, as CheckAccount answers it, so signing in
	// from a device with a narrower grant does not flip it. A person
	// CheckAccount would not find does not sign in either.
	person, err := personAccess(ctx, source, who.UserProfile.ID, map[netip.Addr]tailcfg.PeerCapMap{peer: who.CapMap})
	if err != nil {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "cannot read the tailnet's devices"), nil
	}
	if person == nil {
		return refuse(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "no untagged, unexpired device in the peer list"), nil
	}
	return identityResponse(source.ControlURL(), *who.UserProfile, max(role, person.role)), nil
}

// routesForOthers reports whether node routes a subnet into the tailnet: it
// has approved subnet routes or advertises some. Routers sign in by default:
// LAN traffic a router forwards keeps its LAN source address (Tailscale's
// SNAT covers traffic into the LAN), which WhoIs never matches. Exit node
// routes do not count: they carry traffic out of the tailnet, not into it.
func routesForOthers(node *tailcfg.Node) bool {
	return tsaddr.ContainsNonExitSubnetRoutes(views.SliceOf(node.PrimaryRoutes)) ||
		node.Hostinfo.Valid() && tsaddr.ContainsNonExitSubnetRoutes(node.Hostinfo.RoutableIPs())
}

// CheckAccount re-checks a person from the node's peer list: they must still
// own an untagged, unexpired device this node can see (a person removed from
// the tailnet, or whose share was revoked, has none) and, in policy mode,
// still hold a Silo grant on one of them.
func (p *Provider) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	unavailable := &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE}
	source := p.currentIdentity()
	if source == nil {
		return unavailable, nil
	}
	controlURL := source.ControlURL()
	userID, ok := parseSubject(req.GetExternalSubject(), controlURL)
	if !ok {
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND}, nil
	}
	person, err := personAccess(ctx, source, userID, nil)
	if err != nil {
		return unavailable, nil
	}
	if person == nil {
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_FOUND}, nil
	}
	if p.config.SignInAccess == SignInPolicy && !person.granted {
		return &pluginv1.CheckAccountResponse{Status: pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED}, nil
	}
	return &pluginv1.CheckAccountResponse{
		Status:  pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE,
		Account: identityResponse(controlURL, person.profile, person.role),
	}, nil
}

// personGrants is what the node's peer list says about one tailnet user.
type personGrants struct {
	profile tailcfg.UserProfile
	// granted: a device of theirs holds a Silo grant; role is the highest
	// any of them is granted.
	granted bool
	role    pluginv1.AuthManagedRole
}

// personAccess reads userID's untagged, unexpired devices from the node's
// peer list. It answers nil when they have none, and an error when the node
// cannot answer. known holds grants already read by address, so a device in
// it costs no WhoIs.
func personAccess(ctx context.Context, source identitySource, userID tailcfg.UserID, known map[netip.Addr]tailcfg.PeerCapMap) (*personGrants, error) {
	status, err := source.PeerStatus(ctx)
	if err != nil {
		return nil, err
	}
	if status.BackendState != "Running" {
		return nil, errors.New("tailnet is not running")
	}
	var devices []*ipnstate.PeerStatus
	for _, peer := range status.Peer {
		if peer == nil || peer.UserID != userID || peer.Expired || peer.Tags != nil && peer.Tags.Len() > 0 || len(peer.TailscaleIPs) == 0 {
			continue
		}
		devices = append(devices, peer)
	}
	profile, listed := status.User[userID]
	if len(devices) == 0 || !listed {
		return nil, nil
	}
	found := &personGrants{profile: profile}
	for _, device := range devices {
		caps, err := deviceGrants(ctx, source, device.TailscaleIPs, known)
		if errors.Is(err, local.ErrPeerNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if role, granted := grantedRole(caps); granted {
			found.granted = true
			found.role = max(found.role, role)
		}
	}
	return found, nil
}

// deviceGrants is the app capabilities a device holds toward this node: from
// known when it lists one of the device's addresses, otherwise from WhoIs.
func deviceGrants(ctx context.Context, source identitySource, addresses []netip.Addr, known map[netip.Addr]tailcfg.PeerCapMap) (tailcfg.PeerCapMap, error) {
	for _, address := range addresses {
		if caps, ok := known[address]; ok {
			return caps, nil
		}
	}
	who, err := source.WhoIs(ctx, addresses[0].String())
	if err != nil {
		return nil, err
	}
	return who.CapMap, nil
}

// Authenticate refuses every password. Silo never sends one to a network
// provider; a Silo release that predates the "network" mode would.
func (p *Provider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return refuse(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "Tailscale sign-in takes no password"), nil
}

// siloGrant is one CapSilo value.
type siloGrant struct {
	Role string `json:"role"`
}

// grantedRole reads the CapSilo values a peer holds. Any well-formed value
// grants sign-in; the role is admin when any value says so and user
// otherwise. Without a value the role is left to Silo (unspecified).
// Malformed values grant nothing and are logged without their content.
func grantedRole(caps tailcfg.PeerCapMap) (pluginv1.AuthManagedRole, bool) {
	role, granted := pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false
	for _, raw := range caps[CapSilo] {
		grantRole, ok := parseGrant(raw)
		if !ok {
			slog.Warn("ignoring a malformed siloserver.org/cap/silo grant value")
			continue
		}
		granted = true
		role = max(role, grantRole)
	}
	return role, granted
}

// parseGrant reads one CapSilo value. It is well-formed only as a JSON object
// whose one optional key, "role", is "admin" or "user" (absent or empty means
// user). Anything else, such as null, a misspelled key or "Admin", is
// malformed: a typo in the policy must not grant access.
func parseGrant(raw tailcfg.RawMessage) (pluginv1.AuthManagedRole, bool) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var grant *siloGrant
	if err := decoder.Decode(&grant); err != nil || grant == nil || decoder.More() {
		return pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false
	}
	switch grant.Role {
	case "admin":
		return pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN, true
	case "", "user":
		return pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER, true
	}
	return pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED, false
}

// subjectPrefix scopes user IDs to the control plane that issued them: the
// IDs are not documented as unique across control planes (such as Headscale).
func subjectPrefix(controlURL string) string {
	if parsed, err := url.Parse(controlURL); err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Host) + "|"
	}
	return strings.ToLower(controlURL) + "|"
}

// parseSubject returns the user ID of a subject this node's control plane
// issued.
func parseSubject(subject, controlURL string) (tailcfg.UserID, bool) {
	rest, ok := strings.CutPrefix(subject, subjectPrefix(controlURL))
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return tailcfg.UserID(id), true
}

// identityResponse is what Silo learns about a person. The login name is the
// email only when it is one: GitHub and passkey logins look like alex@github.
// email_verified stays unset, so Silo never matches accounts by it.
func identityResponse(controlURL string, profile tailcfg.UserProfile, role pluginv1.AuthManagedRole) *pluginv1.AuthenticateResponse {
	response := &pluginv1.AuthenticateResponse{
		ExternalSubject: subjectPrefix(controlURL) + strconv.FormatInt(int64(profile.ID), 10),
		Issuer:          controlURL,
		Username:        profile.LoginName,
		DisplayName:     profile.DisplayName,
		PictureUrl:      profile.ProfilePicURL,
		ManagedRole:     role,
	}
	if _, domain, ok := strings.Cut(profile.LoginName, "@"); ok && strings.Contains(domain, ".") {
		response.Email = profile.LoginName
	}
	return response
}

func refuse(denial pluginv1.AuthDenial, detail string) *pluginv1.AuthenticateResponse {
	return &pluginv1.AuthenticateResponse{Denial: denial, DenialDetail: detail}
}
