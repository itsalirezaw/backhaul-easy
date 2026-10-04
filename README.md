# Backhaul Easy

**English** · [فارسی](README.fa.md)

[![Tests](https://github.com/itsalirezaw/backhaul-easy/actions/workflows/ci.yml/badge.svg)](https://github.com/itsalirezaw/backhaul-easy/actions/workflows/ci.yml)

Install and manage the official [Backhaul](https://github.com/Musixal/Backhaul) engine with an interactive menu. Installer and management tools by **alirezaw**: [GitHub](https://github.com/itsalirezaw) · [YouTube](https://www.youtube.com/@ialirezaw).

This is an independent installer, not the upstream Backhaul project. The engine is downloaded from its official release and checked against a pinned SHA-256 hash. Project repository: [itsalirezaw/backhaul-easy](https://github.com/itsalirezaw/backhaul-easy). See [validation status](VALIDATION.md) for completed checks and remaining live deployment tests.

## What it does

Choose one of two modes:

1. **3x-ui panel on Iran.** Users connect to their existing Iran panel inbounds. A VLESS outbound in 3x-ui connects to `127.0.0.1:1080` on Iran. Backhaul carries that connection to a dedicated, automatically installed Xray process on Outside, which provides the Internet exit. The local port is configurable. Both user TCP and UDP can travel inside the VLESS connection.
2. **Forward application ports.** Expose selected ports on Iran and forward them to applications reachable from Outside. Map individual ports, equal-size ranges, or different destination ports and addresses.

The Backhaul **server is Iran** and the **client is Outside**. Outside initiates the tunnel connection to Iran. Set up Iran first and paste its pairing code on Outside. These names describe the Backhaul roles, not where your management panel lives.

This manager operates one tunnel pair per installation. Multiple service mappings share that tunnel. Host default routes, SSH configuration, firewall rules and global kernel network settings are not changed. It does not migrate WG Bridge settings or edit your panel automatically.

## Requirements

Ubuntu 22.04, 24.04 or 26.04 LTS, including point releases; or Debian 12/13, with systemd, root access, and amd64 or arm64. Python 3.10+ is required. The servers must be able to download official release assets over HTTPS.

The installer installs missing prerequisites. To install them explicitly:

```bash
apt-get update && apt-get install -y python3 curl ca-certificates openssl iproute2
```

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/backhaul-easy/main/install.sh)
```

The script is self-contained; the other repository files are not required on the servers. Reopen the installed menu with:

```bash
backhaul-easy
```

### Iran

1. Choose **Set up Iran / Outside**, then **Iran**.
2. Choose **Panel on Iran** for 3x-ui, or **Forward ports** for ordinary port forwarding.
3. Enter Iran's public IP or domain that Outside can reach.
4. Choose a transport. TCP is the default; all seven upstream transports are available. UDP-only transport cannot carry the panel's VLESS TCP connection.
5. Choose the tunnel control port, default **3080**. This is separate from the local panel bridge port, default **1080**. You can change both.
6. Accept the optional settings or open the advanced settings when you need them.
7. Review the displayed settings, confirm, and copy the entire **BHE1.** pairing code.

Allow the selected tunnel port through Iran's provider and host firewalls. Use TCP for TCP/WS and their mux/TLS variants. The UDP transport needs **both TCP and UDP** on the same tunnel port. Restrict access to the Outside server's IP where possible. For panel mode, do not expose the local bridge port publicly.

### Outside

1. Run the same installer and choose **Outside**.
2. Paste the entire pairing code; input is visible. Press Enter to retain suggested settings.
3. Review and confirm. Panel mode installs a separate Xray egress process and checks its local TCP and UDP forwarding. Existing Xray or panel installations are left intact.
4. Run `backhaul-easy doctor` on both servers. A running process or an old handshake log does not prove that user traffic works; complete the real client test below.

The pairing code contains the tunnel token and, in panel mode, the proxy UUID. Keep it out of public recordings. Its checksum detects copying errors; it is not encryption or a signature. Use one code for its intended pair.

## Configure 3x-ui on Iran

Export a panel backup before changing its Xray settings. The installer does not change this panel for you.

### 1. Add the outbound

On Iran, run:

```bash
backhaul-easy panel
```

Copy the generated outbound JSON into **3x-ui → Xray settings → Outbounds → Add → JSON**. Labels can differ between panel versions. Its tag is `backhaul-out`, protocol is `vless`, and address is Iran's `127.0.0.1` with your chosen bridge port. Keep its generated UUID. This port is **VLESS, not SOCKS5**.

Do not use the previous WireGuard `sendThrough: 10.204.0.2` or `interface: wgb-exit` settings for this outbound. The manager has generated the connection it needs. A Dockerized panel must share the host network for host `127.0.0.1` to be reachable; this guide assumes a native installation or host networking.

### 2. Route the intended users

In Routing, add a rule whose **Inbound tags** are the actual tags of the user inbounds you want to tunnel, and whose **Outbound tag** is `backhaul-out`. Place it before broader rules that send those same users to `direct`. Preserve API routing and any intentional blocking rules. Merely moving an outbound to the top does not override an explicit routing rule.

Example rule to merge into `routing.rules` after replacing the placeholder:

```json
{
  "type": "field",
  "inboundTag": ["YOUR_ACTUAL_USER_INBOUND_TAG"],
  "outboundTag": "backhaul-out"
}
```

Add all intended user inbound tags to that list. An inbound tag is its Xray configuration name, not a user's name, UUID, or port number. Leave `routing.domainStrategy` as `AsIs` unless you deliberately need IP-based routing.

### 3. Route panel DNS through the tunnel

For Xray's built-in DNS, merge this **dns object** into the existing configuration, preserving any intentional DNS overrides you need:

```json
{
  "tag": "backhaul-dns",
  "queryStrategy": "UseIPv4",
  "servers": ["8.8.8.8", "1.1.1.1"]
}
```

Then add this rule above rules that would otherwise send these DNS requests directly:

```json
{
  "type": "field",
  "inboundTag": ["backhaul-dns"],
  "outboundTag": "backhaul-out"
}
```

The numeric resolver addresses use UDP port 53. The DNS tag lets routing send those queries through the proxy. This changes Xray's DNS path, not the host resolver configuration. Avoid `localhost` or a local-mode resolver as a fallback when the intention is to send these queries through Outside. Applications on the user's device can have their own DNS behavior; test a real client as well. See the [official Xray DNS documentation](https://xtls.github.io/en/config/dns.html) and [routing documentation](https://xtls.github.io/en/config/routing.html).

### 4. Save and test

Save the panel changes and restart its Xray core. Reconnect one real user and check the Internet exit IP; it should be the Outside server's address. Open several websites and play a video. Confirm user usage counters continue increasing in 3x-ui. The address in the user's connection profile should still be Iran.

If the tunnel is stopped, users assigned to this outbound should lose connectivity rather than silently switch to a direct outbound. Do not configure a direct fallback or balancer if that is your intended behavior.

## Transports and advanced settings

- **TCP:** TCP application streams; optional `accept_udp` also carries UDP payloads over TCP in forwarding mode.
- **TCPMux:** TCP streams using multiplexing.
- **UDP:** UDP application forwarding only; its control connection still uses TCP.
- **WS / WSMux:** TCP streams over WebSocket, without/with multiplexing.
- **WSS / WSSMux:** TCP streams over TLS WebSocket, without/with multiplexing. Generate a self-signed certificate in the wizard or supply existing PEM files.

In panel mode, user UDP is encapsulated by VLESS inside a TCP-capable transport; the underlying Backhaul UDP-only mode is not used. This can have different performance from native UDP.

Advanced settings expose pools, retries, keepalive, heartbeat, channel and mux parameters, socket buffers/MSS, supported PROXY protocol settings, and optional upstream traffic monitoring. Multiplexing settings shared by the two sides must match; changing them after installation may require applying the matching values on the other server. PROXY headers are for compatible destination applications and are disabled in panel mode.

Monitoring is off by default. The optional upstream monitoring HTTP endpoint is unauthenticated and listens publicly; enabling it requires an explicit acknowledgement and appropriate firewall restrictions. Global optimizer and pprof profiling are disabled. The default configuration does not change system network tuning. Forwarding destinations use IPv4 addresses or DNS names; upstream v0.7.2's forwarding parser does not support literal IPv6 destinations. Up to 128 forwarding mappings are accepted per installation.

**Transport security:** TCP, TCPMux, WS and WSMux do not add TLS encryption. The generated VLESS bridge also uses no extra encryption. HTTPS traffic retains its own end-to-end TLS. In pinned Backhaul v0.7.2, WSS clients use `InsecureSkipVerify`; WSS encrypts transport but does **not** authenticate the server certificate. Do not describe this wrapper as adding WireGuard-like security or guaranteeing resistance to filtering. See [upstream TLS dialer](https://github.com/Musixal/Backhaul/blob/v0.7.2/internal/utils/network/ws_dialer.go).

## Management

```bash
backhaul-easy status
backhaul-easy doctor
backhaul-easy logs
backhaul-easy start
backhaul-easy stop
backhaul-easy restart
backhaul-easy ports
backhaul-easy advanced
backhaul-easy pairing
backhaul-easy panel
backhaul-easy upgrade
backhaul-easy uninstall
```

Uninstall requires typing `REMOVE`. It removes only this manager's owned services and files, preserving unrelated applications and dependencies. Modified installation files are preserved or reported for manual attention. Any 3x-ui routing/outbound you added manually must also be updated or removed manually.

Use a newly supplied installer with `bash install.sh --upgrade` to install that bundle's versions while preserving settings. The menu's repair action reinstalls the **already bundled versions**; it does not claim to fetch a future installer. Installed installer copy: `/usr/local/lib/backhaul-easy/install.sh`. `--check` verifies the bundled sources and official engine download without installing; prerequisites must already exist. `--no-menu` installs tools without configuring a tunnel.

## Reproducible build and validation

Pinned engines: Backhaul **v0.7.2** and, for the Outside panel helper, Xray **v26.3.27**. Hashes are embedded in `bootstrap.py` and `panel_support.py`.

```bash
python3 tools/build_installer.py
python3 -m unittest discover -s tests -v
bash -n install.sh
python3 tests/integration_backhaul.py --binary /path/to/verified/backhaul
```

The integration test uses loopback listeners, temporary files and child processes only. It exercises real TCP/UDP payloads for all seven transports. See [validation status](VALIDATION.md) for what was actually run on this bundle. OS detection support is not a claim that every OS/architecture combination has been tested.

## Credits and licensing

Backhaul is by [Musixal and its contributors](https://github.com/Musixal/Backhaul), licensed AGPL-3.0. Xray-core is by [XTLS and contributors](https://github.com/XTLS/Xray-core), licensed MPL-2.0. This installer is provided under AGPL-3.0; see [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md). Official engine archives are downloaded at installation time, not rebranded or bundled in this source package.
