// Package tailscale implements Silo's resident network access provider.
package tailscale

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const ProviderVersion = "tsnet 1.102.4"
const desiredKey = "desired_connected"

type Host interface {
	GetHostInfo(context.Context) (*runtimehost.HostInfo, error)
	ReadInstanceState(context.Context, string) ([]byte, bool, error)
	WriteInstanceState(context.Context, string, []byte) error
	ReportNetworkAccessStatus(context.Context, *pluginv1.NetworkAccessStatus) error
}

type Runner func(context.Context, Host, Config, func(*pluginv1.NetworkAccessStatus)) error

type Provider struct {
	pluginv1.UnimplementedNetworkAccessProviderServer
	host     Host
	config   Config
	run      Runner
	life     chan struct{}
	mu       sync.Mutex
	status   *pluginv1.NetworkAccessStatus
	cancel   context.CancelFunc
	done     chan struct{}
	wake     chan struct{}
	stop     context.CancelFunc
	reported chan struct{}
	restored bool
	closed   atomic.Bool
	// identity is the connected overlay sign-in reads (identity.go); nil
	// while it is not serving.
	identityMu sync.RWMutex
	identity   identitySource
}

// New returns a provider. A nil run uses the tsnet runner, which also feeds
// sign-in; a test runner leaves sign-in unavailable.
func New(host Host, config Config, run Runner) *Provider {
	done := make(chan struct{})
	close(done)
	ctx, stop := context.WithCancel(context.Background())
	p := &Provider{host: host, config: config, run: run, life: make(chan struct{}, 1), done: done,
		wake: make(chan struct{}, 1), stop: stop, reported: make(chan struct{}),
		status: &pluginv1.NetworkAccessStatus{State: "disconnected", ProviderVersion: ProviderVersion}}
	if p.run == nil {
		p.run = func(ctx context.Context, host Host, config Config, publish func(*pluginv1.NetworkAccessStatus)) error {
			return Run(ctx, host, config, publish, p.setIdentity)
		}
	}
	go func() {
		defer close(p.reported)
		p.report(ctx)
	}()
	return p
}

// Restore is called during Configure, after the host broker is bound. It never
// waits for enrollment and does not need a subsequent admin RPC to reconnect.
// Repeated calls do not start another runner or replace later operator intent.
func (p *Provider) Restore(ctx context.Context) error {
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()
	if p.restored {
		return nil
	}
	b, found, err := p.host.ReadInstanceState(ctx, desiredKey)
	if err != nil {
		return stateError(ctx, "cannot read connection intent")
	}
	if found && string(b) != "0" && string(b) != "1" {
		return status.Error(codes.FailedPrecondition, "invalid saved connection intent")
	}
	p.restored = true
	if found && string(b) == "1" {
		p.start()
	} else {
		p.signal()
	}
	return nil
}

func (p *Provider) Connect(ctx context.Context, _ *pluginv1.NetworkAccessConnectRequest) (*pluginv1.NetworkAccessStatus, error) {
	if err := p.acquire(ctx); err != nil {
		return nil, err
	}
	defer p.release()
	if p.cancel != nil {
		select {
		case <-p.done:
			p.cancel()
			p.cancel = nil
		default:
			current := p.snapshot()
			if current.State != "error" {
				return current, nil
			}
			// The overlay may keep retrying after an asynchronous failure.
			// An explicit retry must retire that run before starting another.
			p.cancel()
			p.cancel = nil
		}
	}
	select {
	case <-p.done:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if err := p.host.WriteInstanceState(ctx, desiredKey, []byte("1")); err != nil {
		return nil, stateError(ctx, "cannot save connection intent")
	}
	p.restored = true
	p.start()
	return p.snapshot(), nil
}

func (p *Provider) start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	p.set(&pluginv1.NetworkAccessStatus{State: "connecting", DesiredConnected: true})
	done := p.done
	go func() {
		defer close(done)
		publish := func(s *pluginv1.NetworkAccessStatus) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			s.DesiredConnected = true
			p.setLocked(s)
		}
		err := p.run(ctx, p.host, p.config, publish)
		if ctx.Err() == nil {
			message := "overlay stopped unexpectedly; reconnect to retry"
			var safe *PublicError
			if errors.As(err, &safe) {
				message = safe.Message
			}
			last := p.snapshot()
			publish(&pluginv1.NetworkAccessStatus{State: "error", Error: message,
				Hostname: last.Hostname, Addresses: last.Addresses})
		}
	}()
}

func (p *Provider) Disconnect(ctx context.Context, _ *pluginv1.NetworkAccessDisconnectRequest) (*pluginv1.NetworkAccessStatus, error) {
	if err := p.acquire(ctx); err != nil {
		return nil, err
	}
	defer p.release()
	if err := p.host.WriteInstanceState(ctx, desiredKey, []byte("0")); err != nil {
		return nil, stateError(ctx, "cannot save connection intent")
	}
	p.restored = true
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.set(&pluginv1.NetworkAccessStatus{State: "disconnected"})
	select {
	case <-p.done:
		return p.snapshot(), nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

func (p *Provider) GetStatus(context.Context, *pluginv1.NetworkAccessGetStatusRequest) (*pluginv1.NetworkAccessStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil, status.Error(codes.FailedPrecondition, "provider is closed")
	}
	return proto.Clone(p.status).(*pluginv1.NetworkAccessStatus), nil
}

// Close stops the process without changing the persisted operator intent.
// It waits for the runner and status reporter, and permanently closes the provider.
func (p *Provider) Close() {
	p.life <- struct{}{}
	defer p.release()
	if p.closed.Load() {
		return
	}
	p.closed.Store(true)
	p.stop()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	<-p.done
	<-p.reported
}

// acquire serializes lifecycle changes without keeping canceled RPCs queued
// behind network shutdown or an unavailable state store. Runner state and
// restored are protected by this gate. Atomic closure lets status calls reject
// retired providers without waiting for their lifecycle operations to finish.
func (p *Provider) acquire(ctx context.Context) error {
	select {
	case p.life <- struct{}{}:
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
	if err := ctx.Err(); err != nil {
		p.release()
		return status.FromContextError(err).Err()
	}
	if p.closed.Load() {
		p.release()
		return status.Error(codes.FailedPrecondition, "provider is closed")
	}
	return nil
}

func (p *Provider) release() { <-p.life }

func stateError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Unavailable, message)
}

func (p *Provider) snapshot() *pluginv1.NetworkAccessStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return proto.Clone(p.status).(*pluginv1.NetworkAccessStatus)
}

func (p *Provider) set(s *pluginv1.NetworkAccessStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setLocked(s)
}
func (p *Provider) setLocked(s *pluginv1.NetworkAccessStatus) {
	s.ProviderVersion = ProviderVersion
	if proto.Equal(p.status, s) {
		return
	}
	if p.status.State != s.State {
		slog.Info("network access state changed", "state", s.State)
	}
	p.status = proto.Clone(s).(*pluginv1.NetworkAccessStatus)
	p.signal()
}
func (p *Provider) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// One reporter preserves ordering; periodic retries repair missed status pushes.
func (p *Provider) report(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := p.host.ReportNetworkAccessStatus(call, p.snapshot())
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("network access status delivery failed")
		}
	}
}

// PublicError contains only fixed, operator-safe text, never upstream errors.
type PublicError struct{ Message string }

func (e *PublicError) Error() string { return e.Message }
