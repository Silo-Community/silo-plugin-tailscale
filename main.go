// Command silo-plugin-tailscale serves the resident Tailscale provider over
// Silo's private go-plugin transport. Silo owns its process lifecycle.
package main

import (
	"context"
	_ "embed"
	"os"
	"sync"

	"github.com/Silo-Community/silo-plugin-tailscale/internal/tailscale"
	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/envknob"
	"tailscale.com/logtail"
)

//go:embed manifest.json
var manifestJSON []byte
var version = "0.1.3"

type plugin struct {
	runtimedefault.Server
	pluginv1.UnimplementedNetworkAccessProviderServer
	// Sign-in with tailnet identity: the auth_provider.v1 capability's
	// "network" mode. Only Authenticate, AuthenticatePeer and CheckAccount
	// are served; the rest answer Unimplemented.
	pluginv1.UnimplementedAuthProviderServer
	pluginv1.UnimplementedAuthProviderChecksServer
	pluginv1.UnimplementedNetworkIdentityAuthServer
	mu            sync.RWMutex
	manifest      *pluginv1.PluginManifest
	provider      *tailscale.Provider
	host          tailscale.Host
	configureOnce sync.Once
	configuring   chan struct{}
}

func (p *plugin) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{Manifest: p.manifest}, nil
}
func (p *plugin) Configure(ctx context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	config, err := tailscale.ParseConfig(req.GetConfig())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	host := p.host
	if host == nil {
		if broker := sdkruntime.Host(); broker != nil {
			host = broker
		}
	}
	if host == nil {
		return nil, status.Error(codes.FailedPrecondition, "host broker is not bound")
	}
	p.configureOnce.Do(func() { p.configuring = make(chan struct{}, 1) })
	select {
	case p.configuring <- struct{}{}:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	defer func() { <-p.configuring }()
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	p.mu.Lock()
	previous := p.provider
	p.provider = nil
	p.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
	provider := tailscale.New(host, config, nil)
	if err := provider.Restore(ctx); err != nil {
		provider.Close()
		return nil, err
	}
	p.mu.Lock()
	p.provider = provider
	p.mu.Unlock()
	return &pluginv1.ConfigureResponse{}, nil
}
func (p *plugin) Connect(ctx context.Context, req *pluginv1.NetworkAccessConnectRequest) (*pluginv1.NetworkAccessStatus, error) {
	provider := p.currentProvider()
	if provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin is not configured")
	}
	return provider.Connect(ctx, req)
}
func (p *plugin) Disconnect(ctx context.Context, req *pluginv1.NetworkAccessDisconnectRequest) (*pluginv1.NetworkAccessStatus, error) {
	provider := p.currentProvider()
	if provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin is not configured")
	}
	return provider.Disconnect(ctx, req)
}
func (p *plugin) GetStatus(ctx context.Context, req *pluginv1.NetworkAccessGetStatusRequest) (*pluginv1.NetworkAccessStatus, error) {
	provider := p.currentProvider()
	if provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin is not configured")
	}
	return provider.GetStatus(ctx, req)
}

// signInProvider is the configured provider for a sign-in RPC. Before
// Configure, Silo is told the provider cannot answer yet.
func (p *plugin) signInProvider() (*tailscale.Provider, error) {
	provider := p.currentProvider()
	if provider == nil {
		return nil, status.Error(codes.Unavailable, "plugin is not configured")
	}
	return provider, nil
}
func (p *plugin) Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	provider, err := p.signInProvider()
	if err != nil {
		return nil, err
	}
	return provider.Authenticate(ctx, req)
}
func (p *plugin) AuthenticatePeer(ctx context.Context, req *pluginv1.AuthenticatePeerRequest) (*pluginv1.AuthenticateResponse, error) {
	provider, err := p.signInProvider()
	if err != nil {
		return nil, err
	}
	return provider.AuthenticatePeer(ctx, req)
}
func (p *plugin) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	provider, err := p.signInProvider()
	if err != nil {
		return nil, err
	}
	return provider.CheckAccount(ctx, req)
}

func (p *plugin) currentProvider() *tailscale.Provider {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.provider
}
func main() {
	// Enrollment is controlled only by the encrypted Silo configuration.
	// Do not inherit daemon credentials or forced re-enrollment from the host.
	for _, key := range []string{"TS_AUTHKEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID", "TS_ID_TOKEN", "TS_AUDIENCE", "TS_CONTROL_URL", "TSNET_FORCE_LOGIN"} {
		_ = os.Unsetenv(key)
	}
	// Disable diagnostic uploads as well as both tsnet log callbacks. Auth
	// URLs, keys, ingress tokens and upstream error strings never reach logs.
	envknob.SetNoLogsNoSupport()
	logtail.Disable()
	m, err := manifest.LoadWithChecksum(manifestJSON, version)
	if err != nil {
		panic(err)
	}
	p := &plugin{manifest: m}
	// The runtime registers AuthProviderChecks and NetworkIdentityAuth because
	// the AuthProvider server implements them too.
	sdkruntime.Serve(sdkruntime.ServeConfig{Servers: sdkruntime.CapabilityServers{Runtime: p, NetworkAccessProvider: p, AuthProvider: p}})
}
