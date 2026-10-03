package tailscale

import (
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/protobuf/types/known/structpb"
	"tailscale.com/ipn/ipnstate"
)

func TestConfigAndHostnames(t *testing.T) {
	c, err := ParseConfig(nil)
	if err != nil || c.HostnamePrefix != "silo" {
		t.Fatal(c, err)
	}
	for _, value := range []any{"UPPER", "bad.name", "-bad", "bad-", 42, ""} {
		v, _ := structpb.NewStruct(map[string]any{"hostname_prefix": value})
		if _, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}}); err == nil {
			t.Fatalf("accepted prefix %v", value)
		}
	}
	a := &runtimehost.HostInfo{HostRole: "api"}
	c.HostnamePrefix = "my-silo"
	if got := Hostname(c, a); got != "my-silo" {
		t.Fatalf("hostname must match the configured value exactly: %q", got)
	}
	b := &runtimehost.HostInfo{HostRole: "proxy", NodeID: 1}
	d := &runtimehost.HostInfo{HostRole: "proxy", NodeID: 2}
	if Hostname(c, a) == Hostname(c, b) || Hostname(c, b) == Hostname(c, d) {
		t.Fatal("hosts share hostname")
	}
}

func TestAllListenersAndValidation(t *testing.T) {
	info, _ := newHost().GetHostInfo(t.Context())
	info.Listeners = append(info.Listeners, runtimehost.HostListener{Name: "jellyfin", Address: "127.0.0.1:8096"}, runtimehost.HostListener{Name: "abs", Address: "[::1]:13378"})
	if err := validateHost(info); err != nil {
		t.Fatal(err)
	}
	st := &ipnstate.Status{Self: &ipnstate.PeerStatus{DNSName: "silo.example.test."}, CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true}, CertDomains: []string{"silo.example.test"}}
	s, err := connectedStatus(info, st)
	if err != nil || len(s.Listeners) != 3 || s.Origin != "https://silo.example.test" || s.Listeners[1].Origin != "https://silo.example.test:8096" || s.Listeners[2].Origin != "https://silo.example.test:13378" {
		t.Fatalf("%v %v", s, err)
	}
	st.CertDomains = nil
	if _, err := connectedStatus(info, st); err == nil {
		t.Fatal("HTTPS missing but ready")
	}
	for _, address := range []string{"192.0.2.1:8080", "example.test:8080", "127.0.0.1:0", "127.0.0.1"} {
		info.Listeners[0].Address = address
		if err := validateHost(info); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	info.Listeners[0].Address = "127.0.0.1:8080"
	info.Listeners[1].DefaultPort = 443
	if err := validateHost(info); err == nil {
		t.Fatal("accepted colliding ports")
	}
}

func TestTags(t *testing.T) {
	for _, test := range []struct {
		raw   string
		valid bool
		count int
	}{
		{"", true, 0}, {" tag:silo,tag:media,tag:silo ", true, 2}, {"silo", false, 0}, {"tag:", false, 0}, {"tag:silo,", false, 0},
	} {
		v, _ := structpb.NewStruct(map[string]any{"tags": test.raw})
		got, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}})
		if (err == nil) != test.valid || err == nil && len(got.Tags) != test.count {
			t.Fatalf("tags %q: count=%d err=%v", test.raw, len(got.Tags), err)
		}
	}
}

// Funnel was removed: a saved switch still configures and changes nothing,
// but a malformed value is still refused.
func TestLegacyFunnelSettingIsIgnored(t *testing.T) {
	for value, valid := range map[any]bool{true: true, false: true, "true": false} {
		v, _ := structpb.NewStruct(map[string]any{"funnel": value})
		c, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}})
		if (err == nil) != valid {
			t.Fatalf("funnel %v: %v", value, err)
		}
		if valid && c.HostnamePrefix != "silo" {
			t.Fatalf("funnel %v changed the config: %+v", value, c)
		}
	}
}

func TestSignInAccess(t *testing.T) {
	defaults, err := ParseConfig(nil)
	if err != nil || defaults.SignInAccess != SignInAnyone {
		t.Fatalf("default access = %q, %v", defaults.SignInAccess, err)
	}
	for value, want := range map[string]string{"": SignInAnyone, "anyone": SignInAnyone, "policy": SignInPolicy, "everyone": ""} {
		v, _ := structpb.NewStruct(map[string]any{"sign_in_access": value})
		c, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}})
		if want == "" {
			if err == nil {
				t.Fatalf("access %q accepted", value)
			}
			continue
		}
		if err != nil || c.SignInAccess != want {
			t.Fatalf("access %q = %q, %v", value, c.SignInAccess, err)
		}
	}
}

func TestSubnetRouters(t *testing.T) {
	defaults, err := ParseConfig(nil)
	if err != nil || defaults.RefuseSubnetRouters {
		t.Fatalf("default refuse = %v, %v", defaults.RefuseSubnetRouters, err)
	}
	for value, want := range map[string]*bool{"": new(false), "allow": new(false), "refuse": new(true), "deny": nil} {
		v, _ := structpb.NewStruct(map[string]any{"subnet_routers": value})
		c, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}})
		if want == nil {
			if err == nil {
				t.Fatalf("subnet routers %q accepted", value)
			}
			continue
		}
		if err != nil || c.RefuseSubnetRouters != *want {
			t.Fatalf("subnet routers %q = %v, %v", value, c.RefuseSubnetRouters, err)
		}
	}
}

func TestDiscovery(t *testing.T) {
	defaults, err := ParseConfig(nil)
	if err != nil || !defaults.Discovery {
		t.Fatalf("default discovery = %v, %v", defaults.Discovery, err)
	}
	for value, want := range map[string]*bool{"": new(true), "on": new(true), "off": new(false), "yes": nil} {
		v, _ := structpb.NewStruct(map[string]any{"discovery": value})
		c, err := ParseConfig([]*pluginv1.ConfigEntry{{Key: "tailscale", Value: v}})
		if want == nil {
			if err == nil {
				t.Fatalf("discovery %q accepted", value)
			}
			continue
		}
		if err != nil || c.Discovery != *want {
			t.Fatalf("discovery %q = %v, %v", value, c.Discovery, err)
		}
	}
}
