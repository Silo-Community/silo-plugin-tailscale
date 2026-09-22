package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Silo-Community/silo-plugin-tailscale/internal/tailscale"
	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// lifecycleHost starts each new provider disconnected. These tests exercise
// replacement and RPC synchronization without depending on a real host broker.
type lifecycleHost struct{}

func (lifecycleHost) GetHostInfo(context.Context) (*runtimehost.HostInfo, error) {
	return &runtimehost.HostInfo{}, nil
}
func (lifecycleHost) ReadInstanceState(context.Context, string) ([]byte, bool, error) {
	return nil, false, nil
}
func (lifecycleHost) WriteInstanceState(context.Context, string, []byte) error { return nil }
func (lifecycleHost) ReportNetworkAccessStatus(context.Context, *pluginv1.NetworkAccessStatus) error {
	return nil
}

func TestConfigureValidationKeepsProvider(t *testing.T) {
	host := lifecycleHost{}
	previous := tailscale.New(host, tailscale.Config{}, nil)
	defer previous.Close()
	p := &plugin{host: host, provider: previous}
	config, err := structpb.NewStruct(map[string]any{"hostname_prefix": "INVALID"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Configure(t.Context(), &pluginv1.ConfigureRequest{Config: []*pluginv1.ConfigEntry{{Key: "tailscale", Value: config}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid configuration returned %v", err)
	}
	if p.currentProvider() != previous {
		t.Fatal("invalid configuration replaced the current provider")
	}
	if err := previous.Restore(t.Context()); err != nil {
		t.Fatalf("invalid configuration closed the current provider: %v", err)
	}
}

func TestConfigureKeepsRPCsResponsiveDuringShutdown(t *testing.T) {
	host := lifecycleHost{}
	stopping := make(chan struct{})
	release := make(chan struct{})
	previous := tailscale.New(host, tailscale.Config{}, func(ctx context.Context, _ tailscale.Host, _ tailscale.Config, _ func(*pluginv1.NetworkAccessStatus)) error {
		<-ctx.Done()
		close(stopping)
		<-release
		return ctx.Err()
	})
	p := &plugin{host: host, provider: previous}
	var released sync.Once
	defer func() {
		released.Do(func() { close(release) })
		previous.Close()
		if current := p.currentProvider(); current != nil {
			current.Close()
		}
	}()
	if _, err := p.Connect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	configured := make(chan error, 1)
	go func() { _, err := p.Configure(t.Context(), nil); configured <- err }()
	<-stopping
	for name, operation := range map[string]func(context.Context) error{
		"status":     func(ctx context.Context) error { _, err := p.GetStatus(ctx, nil); return err },
		"connect":    func(ctx context.Context) error { _, err := p.Connect(ctx, nil); return err },
		"disconnect": func(ctx context.Context) error { _, err := p.Disconnect(ctx, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			go func() { result <- operation(t.Context()) }()
			select {
			case err := <-result:
				if status.Code(err) != codes.FailedPrecondition {
					t.Fatalf("retired provider remained available: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RPC blocked behind provider shutdown")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	queued := make(chan error, 1)
	go func() { _, err := p.Configure(ctx, nil); queued <- err }()
	select {
	case err := <-queued:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("canceled reconfiguration returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled Configure remained queued behind shutdown")
	}
	released.Do(func() { close(release) })
	if err := <-configured; err != nil {
		t.Fatal(err)
	}
	current := p.currentProvider()
	if current == nil || current == previous {
		t.Fatal("Configure did not install the replacement provider")
	}
	if _, err := previous.Connect(t.Context(), nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("retired provider accepted a raced Connect")
	}
	if s, err := previous.GetStatus(t.Context(), nil); s != nil || status.Code(err) != codes.FailedPrecondition {
		t.Fatal("retired provider exposed stale status to a raced GetStatus")
	}
}
