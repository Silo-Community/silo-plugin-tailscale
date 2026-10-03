package tailscale

import (
	"fmt"
	"regexp"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/protobuf/types/known/structpb"
	"tailscale.com/tailcfg"
)

type Config struct {
	HostnamePrefix, AuthKey string
	Tags                    []string
	// SignInAccess is who may sign in to Silo with their tailnet identity:
	// SignInAnyone or SignInPolicy.
	SignInAccess string
	// RefuseSubnetRouters keeps devices that route a subnet into the tailnet
	// from signing in, for tailnets whose routers rewrite forwarded LAN
	// traffic to their own Tailscale address.
	RefuseSubnetRouters bool
}

// Sign-in access modes. Anyone whose untagged device reaches Silo can sign in
// by default; policy mode admits only peers granted CapSilo.
const (
	SignInAnyone = "anyone"
	SignInPolicy = "policy"
)

var prefixPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

func ParseConfig(entries []*pluginv1.ConfigEntry) (Config, error) {
	c := Config{HostnamePrefix: "silo", SignInAccess: SignInAnyone}
	seen := false
	for _, entry := range entries {
		if entry.GetKey() != "tailscale" || seen {
			return c, fmt.Errorf("unexpected or duplicate configuration section")
		}
		seen = true
		for key, value := range entry.GetValue().GetFields() {
			if key == "funnel" {
				// Funnel was removed; installs that saved the switch still
				// configure, and the value is ignored.
				if _, ok := value.GetKind().(*structpb.Value_BoolValue); !ok {
					return c, fmt.Errorf("funnel must be a boolean")
				}
				continue
			}
			if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
				return c, fmt.Errorf("configuration fields must be strings")
			}
			switch key {
			case "hostname_prefix":
				c.HostnamePrefix = value.GetStringValue()
			case "auth_key":
				c.AuthKey = value.GetStringValue()
			case "tags":
				seenTags := map[string]bool{}
				raw := strings.TrimSpace(value.GetStringValue())
				if raw == "" {
					continue
				}
				for _, tag := range strings.Split(raw, ",") {
					tag = strings.TrimSpace(tag)
					if tailcfg.CheckTag(tag) != nil {
						return c, fmt.Errorf("tags must be comma-separated Tailscale tags such as tag:silo")
					}
					if !seenTags[tag] {
						c.Tags = append(c.Tags, tag)
						seenTags[tag] = true
					}
				}
				if len(c.Tags) > 32 {
					return c, fmt.Errorf("at most 32 tags may be advertised")
				}
			case "sign_in_access":
				switch access := value.GetStringValue(); access {
				case "":
				case SignInAnyone, SignInPolicy:
					c.SignInAccess = access
				default:
					return c, fmt.Errorf("sign-in access must be anyone or policy")
				}
			case "subnet_routers":
				switch value.GetStringValue() {
				case "", "allow":
				case "refuse":
					c.RefuseSubnetRouters = true
				default:
					return c, fmt.Errorf("subnet routers must be allow or refuse")
				}
			default:
				return c, fmt.Errorf("unexpected configuration field")
			}
		}
	}
	if !prefixPattern.MatchString(c.HostnamePrefix) {
		return c, fmt.Errorf("hostname must be 1–32 lowercase letters, digits or internal hyphens")
	}
	if c.AuthKey != "" && (!strings.HasPrefix(c.AuthKey, "tskey-auth-") || strings.ContainsAny(c.AuthKey, " \r\n\t")) {
		return c, fmt.Errorf("auth key must be a Tailscale auth key")
	}
	return c, nil
}

func Hostname(c Config, info *runtimehost.HostInfo) string {
	if info.HostRole == runtimehost.HostRoleProxy {
		return fmt.Sprintf("%s-proxy-%d", c.HostnamePrefix, info.NodeID)
	}
	return c.HostnamePrefix
}
