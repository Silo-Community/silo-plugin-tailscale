# Tailscale for Silo

Access Silo over HTTPS through your Tailscale network. No separate Tailscale daemon or port forwarding required.

## Setup

Requires a Silo server with network-access plugin support, with MagicDNS and HTTPS certificates enabled in Tailscale.

1. Install **Tailscale** from the plugin catalog in Silo (enable **Include approved community plugins** in plugin settings). To install manually instead, [build the plugin](docs/DEVELOPMENT.md#build-and-verify), extract the ZIP, and upload its `plugin` executable.
2. Enable the plugin, choose a hostname, and optionally enter a Tailscale auth key.
3. Save, then select **Connect** in **Settings > Network Access**. Sign in if prompted.
4. Open the reported HTTPS URL from a device running Tailscale.

## Funnel

Optional public access. Disabled by default.

> CAUTION: Exposes Silo to the open public internet, you probably don't want to do this.
> This feature requires Funnel authorization in your Tailscale account and ACL policy file.
> Funnel is not well suited to streaming video. Proceed at your own risk.

[Developer documentation](docs/DEVELOPMENT.md)

## Community maintenance

This is an approved community plugin maintained in the
[`Silo-Community`](https://github.com/Silo-Community) organization by
[ironicbadger](https://github.com/ironicbadger). Use
[GitHub Issues](https://github.com/Silo-Community/silo-plugin-tailscale/issues)
for support and bug reports. Security reports should follow
[`SECURITY.md`](SECURITY.md).

Licensed under the [MIT License](LICENSE).
