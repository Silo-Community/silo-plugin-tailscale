# Development and technical reference

[Back to the README](../README.md).

Built against [SDK v0.16.1](https://github.com/Silo-Server/silo-plugin-sdk/releases/tag/v0.16.1)
and the server's [network-access branch, PR #1096](https://github.com/Silo-Server/silo-server/pull/1096),
following [issue #1001](https://github.com/Silo-Server/silo-server/issues/1001#issuecomment-5641730352).
The server PR is still a prerequisite until merged and released.

## Build and verify

Requires Go 1.26.7 or later, Python 3.9 or later, and Make. CI uses Go 1.26.7
and Python 3.13. Run from this repository:

```sh
make check
make audit
make build
make dist VERSION=0.2.0
```

`plugin` is the local executable. `dist/` contains Linux amd64, Linux arm64,
and macOS arm64 archives. Each ZIP archive contains `plugin`, a manifest carrying
the executable's SHA-256 checksum, and licenses. The embedded manifest also
computes its checksum at runtime. Packaging verifies binary architecture, archive
permissions, manifests and checksums before replacing `dist/`. A successful build
replaces previous distribution files, including archives for older versions.

Binaries omit checkout paths and Git metadata. ZIP entries have fixed timestamps,
order and permissions. Builds with the same source, Go toolchain, Python and zlib
versions produce identical archives. CI runs two complete builds and compares
archive checksums for every change without publishing a release.

`make audit` uses pinned govulncheck to scan imported packages against the online
Go vulnerability database. It scans published module versions, including Tailscale,
so the local storage adaptation cannot hide upstream advisories. This online check
runs separately from `make check` and also runs in CI.

**Use Make rather than plain `go build`.** The pinned Tailscale dependency needs
the storage adaptations described below. An unadapted build fails on the missing
`NoLocalState` field instead of silently writing private state to disk.

## Configure

1. Run Silo with the network-access server support. Check
   `GET /api/v2/network-access/capabilities`. This version supports one API host
   plus proxy nodes; transcode nodes do not run this plugin. The server currently
   requires the API host and proxies to share an OS and architecture.
2. Enable MagicDNS and HTTPS certificates in your Tailscale admin console.
   Certificate issuance puts the tailnet DNS name in public certificate
   transparency logs. Use non-sensitive hostnames.
3. Extract the matching ZIP and upload its `plugin` executable through Silo's plugin installation flow. Then
   enable the installation. Choose a hostname; the API host uses the value exactly as entered. The default yields
   `silo` and `silo-proxy-<node id>`. Use distinct hostnames for separate
   deployments. Tailscale may disambiguate existing names; status reports the
   actual assigned DNS name.
4. Optionally save a Tailscale auth key in the plugin's password field. For
   multiple hosts use a reusable key, with tags/preapproval configured according
   to your tailnet policy. Leave it empty for interactive enrollment. The key is
   only used when a node needs enrollment; replacing it does not replace an
   existing identity.
5. Select **Connect** in Settings > Network Access. Each host reports its own
   authorization URL when a login is needed. Approve the device in Tailscale if
   your policy requires it. Enrollment continues after the API request returns.
6. Use the reported HTTPS origin in a Silo client on a tailnet-connected device.
   Allow the relevant ports through your tailnet access policy: API 443,
   Jellyfin 8096, Audiobookshelf 13378 by default. All exposed listeners use TLS.

The API listener is always exposed. Enabled Jellyfin and Audiobookshelf listeners
are exposed on the API host; proxies expose only their API listener. Host-provided
port overrides are honored. Every listener must bind successfully before status
becomes `connected`. The server handles per-access-path stream URL selection.

**Disconnect** closes listeners, streams, and WebSocket tunnels and saves the
disconnected intent. It retains node identity. A process restart reconnects only
when the last saved intent was connected. A non-running Tailscale backend
clears exposed origins until it becomes ready again. For a terminal provider error,
fix the reported cause and select Connect to retry. Failed state writes return an
error and do not pretend the new intent was saved.

Enrollment failures report a safe error while Tailscale continues its own retries.
Selecting Connect during an error closes the previous run before retrying, so two
nodes cannot use the same identity concurrently. Configuration changes also wait
for the old node and its status reporter to finish.

## Security and state

- Node keys, profiles, TLS private keys, ACME account state and connection intent
  use the host's encrypted per-instance store. Nothing is persisted by the plugin
  to local state files. The host separates the API and proxy state scopes.
- Overlay state uses a versioned envelope to distinguish deleted keys from empty
  values. Existing unwrapped state remains readable and is upgraded on its next
  write; deletion uses a tombstone because the host store has no delete operation.
- Each run reads fresh host metadata and its ingress token. The token remains in
  memory. Requests preserve Host and replace forwarding metadata with the actual
  overlay peer, HTTPS scheme, and host token. Targets must be loopback IPs.
- HTTP range requests, streaming responses, and WebSocket upgrades use Go's
  standard reverse proxy. There is no write timeout on long playback responses.
- Authorization URLs appear only in `awaiting_authorization` status. Provider
  logs contain fixed messages and state names; upstream errors, URLs, tokens and
  keys are excluded. Tailscale log uploads and local logtail buffers are disabled.
- Identity-based Silo login, arbitrary upstream URLs, multiple API
  replicas, and non-Tailscale providers are outside this plugin's scope.

## Tailscale storage adaptations

Tailscale is pinned to **v1.102.4**. Its public `Store` field does not fully satisfy
Silo's no-files contract: tsnet creates logtail files, and ACME uses a certificate
directory for custom stores outside Kubernetes.

[`scripts/prepare_tailscale.py`](../scripts/prepare_tailscale.py) verifies the downloaded module archive against its
committed `go.sum` checksum, recreates ignored build storage from that archive,
and applies exact-match edits to two source files:

1. Add `tsnet.Server.NoLocalState`, require an external store, and skip the local
   state directory and logtail setup when enabled.
2. Route certificate and ACME state through any custom state store, rather than
   restricting that behavior to Kubernetes.

The module cache and committed go.mod stay unchanged. An alternate build modfile
points only Tailscale at the adapted source. The preparation script checks the
exact version and fails if patch context changes. Changes or added files in a
previous `.build/tailscale` tree cannot survive preparation. The Go module retains
upstream licenses in the copied source. Revisit these adaptations on every dependency
update; replace them with upstream APIs when equivalent controls become available.
This is a deliberate maintenance cost, not an unmodified upstream tsnet build.

## Validation scope

`make check` runs dependency-integrity and packaging regressions; race-enabled
lifecycle, configuration, state, proxy and gRPC process tests; and an ACME storage
regression inside the adapted upstream package. Network tests cover enrollment
errors, listener failures and recovery, certificate cancellation, and streaming
and WebSocket shutdown. Real tsnet tests use local control/DERP/STUN servers,
verify identity retention after restart without an auth key, and check for local
files in a separate production process, where Tailscale's test-only log suppression
does not apply. The tests need no real tailnet credentials. `make dist`
cross-compiles all listed platforms.

Before release, validate on the server branch with a real tailnet:

- Interactive and reusable-key enrollment, device approval, TLS issuance/renewal.
- Host/plugin restart with identity retention and disconnected-intent retention.
- Silo sign-in, playback, seeking, events, and WebSockets over the reported origin.
- Jellyfin and Audiobookshelf login, playback, and progress updates.
- API plus proxy nodes: distinct identities and tailnet stream URLs, with fallback
  when a proxy disconnects. Disconnect during active playback and WebSockets.

Real-tailnet/server playback QA has not been performed by the automated tests.
No Apple or Android API changes are needed: clients install Tailscale separately
and use the provider's reported server URL.

## HTTPS and tags

The plugin automatically serves Silo over HTTPS using an embedded `tsnet` node. It does not require or configure a separate host `tailscaled` process or `tailscale serve` command. Enable MagicDNS and HTTPS certificates in the tailnet before connecting. A node can join the tailnet before its HTTPS certificate is ready. The plugin reports that distinction and retries certificate issuance with backoff from 15 seconds to five minutes, honoring a longer certificate-authority retry delay. It advertises a usable HTTPS origin only after certificate acquisition and listener setup succeed.

Optional **Tags** accepts comma-separated Tailscale tags, such as `tag:silo,tag:media`. These tags apply to every plugin host and require authorization in the tailnet policy or authentication key. Changing tags may affect access under the tailnet policy.

Funnel was removed. Every listener is tailnet-only, so every proxied connection comes from a tailnet peer. `ListenTLS` brings the node up before listening, which clears any Serve/Funnel configuration an earlier release persisted; an install that had Funnel on stops answering publicly at the first start of this version. A saved `funnel` value is still accepted and ignored, so upgraded installs configure.

## Sign-in with tailnet identity

The manifest declares an `auth_provider.v1` capability with the SDK's `network` auth mode, and the process serves `NetworkIdentityAuth.AuthenticatePeer` and `AuthProviderChecks.CheckAccount` (`internal/tailscale/identity.go`):

- The proxy replaces any client value of `X-Silo-Ingress-Peer` with the connection's tailnet address. Silo honours it only next to the ingress token. A request that carries forwarding headers (`relayHeaders`, or any `Tailscale-*` header from Serve) came through a relay on another device, whose owner is not the requester, so it gets no peer.
- `AuthenticatePeer` calls WhoIs on that address. It refuses tagged nodes, nodes with an expired key, unknown peers, subnet routers (approved or advertised routes other than exit routes) when **Subnet routers** is set to `refuse`, people `CheckAccount` would not find and, with **Who can sign in** set to `policy`, peers without a `siloserver.org/cap/silo` grant. The subject is `<control host>|<user ID>`, so the same person signs in to the same account from any device. The role is the person's, as `CheckAccount` computes it, not the requesting device's alone. The login name is passed as the email only when it is one (`alice@github` is not), and `email_verified` stays unset.
- Subnet routers sign in by default. WhoIs matches only a node's own addresses, and Tailscale keeps the source address of LAN traffic a router forwards into the tailnet (`--snat-subnet-routes` covers traffic into the LAN), so a connection from a router's own address is the router's. `refuse` is for tailnets whose routers rewrite forwarded traffic to their own address.
- `CapSilo` values are JSON objects whose only key, `role`, is optional: `{"role":"admin"}` maps to the Silo admin role, `{"role":"user"}` or `{}` to user, no value to "leave the role alone". Anything else (null, unknown keys, an unknown role such as `Admin`) is malformed and grants nothing.
- `CheckAccount` reads the node's peer list: the person needs an untagged device with an unexpired key that the node can see (and, in policy mode, a grant on one of them). The role is the highest across their devices. Without a connected node it answers `UNAVAILABLE`, so Silo retries instead of signing people out.
- `Authenticate` refuses every password, so a Silo release that predates the `network` mode cannot route passwords here.

`TestSignInIdentifiesTailnetPeers` runs this against two real `tsnet` nodes and Tailscale's test control server.

Exit-node routing is not currently provided by this plugin. Its embedded network stack carries the plugin's connections, not the Silo process's general outbound traffic. An exit-node selector must not imply that metadata downloads or other Silo requests would use it. Use host-level Tailscale routing when that is the intended behavior.
