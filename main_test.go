package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestManifest(t *testing.T) {
	m, err := manifest.Load(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	if m.Capabilities[0].GetNetworkAccessProvider().GetProvider() != "tailscale" {
		t.Fatal("missing provider descriptor")
	}
	fields := m.GlobalConfigSchema[0].AdminForm.Fields
	if fields[1].Key != "auth_key" || !fields[1].Secret || fields[1].Control != pluginv1.AdminFormControl_ADMIN_FORM_CONTROL_PASSWORD {
		t.Fatal("auth key is not secret")
	}
	if !manifest.AuthProviderUsesNetworkIdentity(m.Capabilities[1]) {
		t.Fatal("missing the network sign-in capability")
	}
	for _, field := range fields {
		if field.Key == "funnel" {
			t.Fatal("Funnel is still offered")
		}
	}
}

// The process serves sign-in on the services Silo calls for the "network"
// auth mode, even before it is configured.
func TestPluginServesSignIn(t *testing.T) {
	p := &plugin{}
	var _ pluginv1.AuthProviderServer = p
	var _ pluginv1.AuthProviderChecksServer = p
	var _ pluginv1.NetworkIdentityAuthServer = p
	if _, err := p.AuthenticatePeer(t.Context(), &pluginv1.AuthenticatePeerRequest{PeerAddress: "100.64.0.7"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("unconfigured AuthenticatePeer = %v, want Unavailable", err)
	}
	if _, err := p.CheckAccount(t.Context(), &pluginv1.CheckAccountRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("unconfigured CheckAccount = %v, want Unavailable", err)
	}
}

type testHost struct {
	pluginv1.UnimplementedRuntimeHostServer
	mu       sync.Mutex
	values   map[string][]byte
	requests chan struct{}
}

func (h *testHost) ReadInstanceState(_ context.Context, r *pluginv1.ReadInstanceStateRequest) (*pluginv1.ReadInstanceStateResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, found := h.values[r.Key]
	return &pluginv1.ReadInstanceStateResponse{Value: append([]byte{}, b...), Found: found}, nil
}
func (h *testHost) WriteInstanceState(_ context.Context, r *pluginv1.WriteInstanceStateRequest) (*pluginv1.WriteInstanceStateResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.values[r.Key] = append([]byte{}, r.Value...)
	return &pluginv1.WriteInstanceStateResponse{}, nil
}
func (h *testHost) ReportNetworkAccessStatus(context.Context, *pluginv1.ReportNetworkAccessStatusRequest) (*pluginv1.ReportNetworkAccessStatusResponse, error) {
	return &pluginv1.ReportNetworkAccessStatusResponse{}, nil
}
func (h *testHost) GetHostInfo(context.Context, *pluginv1.GetHostInfoRequest) (*pluginv1.GetHostInfoResponse, error) {
	h.requests <- struct{}{}
	// An incomplete host contract deliberately stops before contacting any
	// real tailnet. Observing this call proves automatic startup reconnect.
	return &pluginv1.GetHostInfoResponse{HostRole: "api"}, nil
}

func TestProcessBrokerAndAutomaticReconnect(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "plugin")
	if out, err := exec.Command("go", "build", "-ldflags=-X main.version=0.0.0-contract-test", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	binary, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	expectedChecksum := hex.EncodeToString(digest[:])
	h := &testHost{values: map[string][]byte{"desired_connected": []byte("1")}, requests: make(chan struct{}, 4)}
	start := func() *sdkruntime.Client {
		client := goplugin.NewClient(&goplugin.ClientConfig{
			HandshakeConfig: sdkruntime.HandshakeConfig(), Plugins: sdkruntime.DefaultPluginSet(sdkruntime.CapabilityServers{}),
			Cmd: exec.Command(bin), AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
			Logger: hclog.NewNullLogger(), SyncStdout: io.Discard, SyncStderr: io.Discard,
		})
		t.Cleanup(client.Kill)
		rpc, err := client.Client()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := rpc.Dispense(sdkruntime.PluginSetName)
		if err != nil {
			t.Fatal(err)
		}
		rt := raw.(*sdkruntime.Client)
		id := rt.Broker().NextId()
		go rt.Broker().AcceptAndServe(id, func(options []grpc.ServerOption) *grpc.Server {
			s := grpc.NewServer(options...)
			pluginv1.RegisterRuntimeHostServer(s, h)
			return s
		})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if _, err := rt.Runtime().BindHostBroker(ctx, &pluginv1.BindHostBrokerRequest{BrokerId: id}); err != nil {
			t.Fatal(err)
		}
		m, err := rt.Runtime().GetManifest(ctx, &pluginv1.GetManifestRequest{})
		if err != nil || m.GetManifest().GetChecksum() != expectedChecksum || m.GetManifest().GetVersion() != "0.0.0-contract-test" {
			t.Fatalf("manifest: %v %v", m, err)
		}
		if _, err := rt.Runtime().Configure(ctx, &pluginv1.ConfigureRequest{}); err != nil {
			t.Fatal(err)
		}
		return rt
	}
	rt := start()
	select {
	case <-h.requests:
	case <-time.After(5 * time.Second):
		t.Fatal("Configure did not restore connected intent")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s, err := rt.NetworkAccessProvider().Disconnect(ctx, &pluginv1.NetworkAccessDisconnectRequest{})
	if err != nil || s.State != "disconnected" || s.DesiredConnected {
		t.Fatalf("disconnect: %v %v", s, err)
	}
	second := start()
	s, err = second.NetworkAccessProvider().GetStatus(ctx, &pluginv1.NetworkAccessGetStatusRequest{})
	if err != nil || s.State != "disconnected" || s.DesiredConnected {
		t.Fatalf("restored disconnect: %v %v", s, err)
	}
	if _, err := second.NetworkAccessProvider().Connect(ctx, &pluginv1.NetworkAccessConnectRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.requests:
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not start provider")
	}
}
