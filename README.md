# Tailscale for Silo

Access Silo over HTTPS through your Tailscale network. No separate Tailscale daemon or port forwarding required.

## Setup

Requires a Silo server with network-access plugin support, with MagicDNS and HTTPS certificates enabled in Tailscale.

1. Install **Tailscale** from the plugin catalog in Silo (enable **Include approved community plugins** in plugin settings). To install manually instead, [build the plugin](docs/DEVELOPMENT.md#build-and-verify), extract the ZIP, and upload its `plugin` executable.
2. Enable the plugin, choose a hostname, and optionally enter a Tailscale auth key.
3. Save, then select **Connect** in **Settings > Network Access**. Sign in if prompted.
4. Open the reported HTTPS URL from a device running Tailscale. Silo apps with server discovery find a server whose hostname is `silo` on their own; for another hostname, type just that name. Check the hostname in the reported URL: if an older `silo` machine is still in your tailnet (for example after a reinstall), the new node is named `silo-1`, and apps probing `silo` reach the old one. Remove the stale machine in the Tailscale admin console. Turn **Discovery** off to keep port 80 closed.

## Sign in with Tailscale

People whose device reaches Silo over Tailscale can sign in as the device's owner, with no password: a TV signed in to Tailscale gets a "Continue as" button. Turn it on under **Settings > Sign-in > Network sign-in** in Silo (Silo with network identity sign-in support is required).

- **Who can sign in.** By default, anyone whose untagged device reaches the Silo node, including people you share the node with. Set **Who can sign in** to *Only people granted siloserver.org/cap/silo* to require a grant. Tagged devices never sign in this way.
- **Roles.** A grant in your tailnet policy sets the Silo role:

  ```hujson
  "grants": [
    {"src": ["group:family-admins"], "dst": ["tag:silo"],
     "app": {"siloserver.org/cap/silo": [{"role": "admin"}]}},
    {"src": ["autogroup:member", "autogroup:shared"], "dst": ["tag:silo"],
     "app": {"siloserver.org/cap/silo": [{"role": "user"}]}}
  ]
  ```

  `{"role":"admin"}` makes someone a Silo admin; `{"role":"user"}` (or `{}`) a regular user. Any other value, such as `{"role":"Admin"}` or a misspelled key, grants nothing. A person's role is the highest any of their devices is granted, because a Silo account has one role: a grant that depends on the device (posture or source) decides which devices can sign in, not which role a device gets. Without a grant the role is left to Silo, so removing someone's admin grant does not demote them: grant `{"role":"user"}` instead. Anyone who can edit the tailnet policy can make themselves a Silo admin. When an account also signs in through Silo's main sign-in provider (OIDC or LDAP), that provider sets its role instead.
- **Removal.** Someone removed from the tailnet, or whose share is revoked, can no longer reach Silo, and Silo signs their sessions out at its next access re-check.
- **Shared devices.** Everyone using a device signs in as whoever signed that device in to Tailscale, with that person's role, and can link that person's identity to their own Silo account. Sign shared TVs in to Tailscale as someone without an admin grant; Silo profiles keep the household's watching apart.
- **Relays.** A device that forwards other people's traffic to Silo under its own Tailscale address (a reverse proxy, Tailscale Serve or Funnel on another machine, a NAT or Docker host) would make everyone behind it look like its owner. Requests that carry forwarding headers (`X-Forwarded-For`, `Forwarded`, `Via`, Tailscale Serve's headers) get no "Continue as" button. A plain TCP forwarder or NAT shows none: tag every device that relays traffic to Silo.
- **Subnet routers.** A subnet router signs in as its owner like any other device. Machines on the LAN behind it reach Silo with their own LAN addresses, which Tailscale matches to no one, so they get no "Continue as". If one of your routers rewrites forwarded LAN traffic to its own Tailscale address, set **Subnet routers** to **Cannot sign in**. Exit nodes are not affected.

Funnel (public internet access) was removed: Silo is reachable only from your tailnet. An install that had it on stops answering publicly at the first start of this version.

[Developer documentation](docs/DEVELOPMENT.md)

## Community maintenance

This is an approved community plugin maintained in the
[`Silo-Community`](https://github.com/Silo-Community) organization by
[ironicbadger](https://github.com/ironicbadger). Use
[GitHub Issues](https://github.com/Silo-Community/silo-plugin-tailscale/issues)
for support and bug reports. Security reports should follow
[`SECURITY.md`](SECURITY.md).

Licensed under the [MIT License](LICENSE).
