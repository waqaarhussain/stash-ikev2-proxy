# Stash IKEv2 Proxy

Stash version of the WireGuard/IKEv2 proxy exit project. Stash connects to the VPS using Shadowsocks. The VPS uses sing-box to relay traffic through the HTTP, SOCKS5 or Shadowsocks upstream assigned to that profile. Upstream credentials stay on the VPS.

Each device and country combination gets a separate private HTTPS config URL. For example, an Apple TV can import a US profile and a UK profile. Both use that Apple TV’s Control D resolver. Another device can use the same exits with its own resolver and profile credentials.

## Install on a fresh VPS

Use an AMD64 Ubuntu or Debian VPS with systemd and a public IPv4 address. Allow inbound TCP 80 for certificate issuance and renewal, TCP 8443 for profile URLs, and TCP 20000 through 20127 for the profile listeners. Allow UDP in the same profile port range if using UDP-capable exits. The installer adds those rules when UFW is active. Configure any provider firewall separately.

Run as root.

```bash
curl -fsSL https://raw.githubusercontent.com/waqaarhussain/stash-ikev2-proxy/main/install.sh -o /tmp/stash-exit-install.sh && bash /tmp/stash-exit-install.sh
```

The installer installs checksummed releases of sing-box and Caddy. Caddy obtains a trusted certificate for the VPS IP. Installation reports readiness after the HTTPS health check verifies that certificate. For a failed certificate check, verify public reachability on TCP 80 and 8443 and inspect `journalctl -u stash-exit-https`. Rerunning the installer on the same VPS preserves its existing device, exit and profile registry.

## Add an exit and import a profile

1. Run `add` and give the exit a name such as **US** or **UK**. Enter the provider's host, port and credentials. For IP-allowlisted upstreams, allowlist the VPS IP with the provider.
2. Run `new` to add a device. With no saved devices it goes straight to the name prompt. Paste its full Control D DoH URL. The helper confirms the saved URL and prints a profile link for each existing exit.
3. Import the links in Stash using **Download from URL** and select **Rule** mode. The config filename uses the exit label, such as `US.yaml`. Switch countries by switching profiles in Stash.
4. Adding a country with `add` automatically creates and prints a new link for every saved device, reusing each device’s saved DNS. Use `new` with an existing device to create a missing profile for a selected exit.

`link` lists device and country pairs by number, then prints only the selected profile URL. Treat these links as passwords. Each URL can download a config containing credentials for its VPS listener.

| Command | Action |
| --- | --- |
| `add` | Add an HTTP, SOCKS5 or Shadowsocks exit |
| `new` | Add a device for all exits, or create a missing device/exit profile |
| `link` | Retrieve a profile's private HTTPS URL |
| `manage` | Edit or remove an exit, change device DNS, list or revoke profiles |
| `bench` | Check each upstream's public exit identity and request time using a TCP HTTPS request |

## Routing and DNS

The profile routes app traffic captured by Stash through its selected exit, including YouTube. Traffic destined for `45.88.89.23` leaves directly from the VPS, bypassing the selected upstream proxy. This exception matches the destination IP. The per-device Control D endpoint uses a direct DoH connection. When the VPS receives a destination hostname, sing-box resolves it with that same device’s Control D endpoint. sing-box uses the VPS system resolver to look up upstream proxy hostnames.

HTTP exits carry TCP only. SOCKS5 and Shadowsocks can carry UDP when the provider supports relay and you enable it when adding the exit. The upstream failure path has no direct app traffic fallback. The app profile is IPv4-oriented. This is a proxy tunnel for Stash-managed traffic.

## Operation

Exit edits apply on the VPS and keep existing links valid. Older `config.yaml` links still work. Run `link` for the country-named URL. Refresh the profile in Stash when changing a device’s DNS or an exit’s UDP setting. Revoking a profile removes both its download URL and its server-side listener. Changes to the registry check the generated engine configuration, restart the engine briefly and restore the previous configuration if listener startup fails.

Back up `/var/lib/stash-ikev2-proxy/state.json` privately. It contains the upstream credentials, device DNS URLs and profile credentials. Runtime services are `stash-exit-engine`, `stash-exit-profiles` and `stash-exit-https`.

Verify the exit IP and Control D resolver on one device before onboarding the others. Verify Apple TV independently.
