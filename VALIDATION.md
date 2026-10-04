# Validation status

Date: 2026-10-04. This record separates local checks from live Linux deployment.

## Completed

- **71 offline unit tests passed** on Windows using Python 3.12. The suite covers both roles and all seven official transport configuration schemas, pairing, malformed inputs, port mappings, receipt ownership, failed updates, interrupted updates, and rollback of the dedicated panel helper.
- Reproducible standalone installer build: two builds produce identical bytes; decoded embedded modules match their source files; modules parse using Python 3.10 syntax.
- Bash syntax validation and the standalone installer's help command using Git Bash.
- Official Xray **v26.3.27**, Windows amd64 asset: SHA-256 verified against GitHub release metadata. `xray run -test` accepted the generated dedicated proxy configuration. A temporary Xray child process successfully relayed authenticated VLESS TCP and UDP random echo payloads on loopback. The test process and temporary directory were removed. No installed services were changed.

The Windows Xray archive used for this check had SHA-256 `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad`. It is a test-only asset and is not used by the Linux installer.

## Still required before claiming a tested production release

- Actual Backhaul **v0.7.2** payload tests for all seven transports on Linux. `tests/integration_backhaul.py` is supplied for this purpose. It checks two distinct mappings per transport, real TCP echo traffic and supported UDP traffic, with temporary processes and loopback addresses only.
- Linux systemd install, reboot persistence, upgrade, mode change and uninstall checks on a disposable VM. These lifecycle paths have mock-based unit coverage, not a successful live systemd run in this session.
- Complete Iran-to-Outside test using a real 3x-ui user: outbound/routing/DNS selection, observed exit IP, TCP and UDP applications, reconnect behavior, and failure behavior when the tunnel stops.
- arm64 and each advertised distribution/point release have not been independently exercised.

SSH attempts to the available test servers timed out before authentication, so the Linux tests and live deployment could not be performed. No Backhaul services were deployed to those servers.

## Reproduce local checks

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_installer.py
bash -n install.sh
bash install.sh --help
```

For Linux payload integration, obtain the official release, verify the relevant SHA-256 from `bootstrap.py`, then run:

```bash
python3 tests/integration_backhaul.py --binary /absolute/path/to/backhaul
```

The integration runner does not install systemd services, change routing/firewalls/sysctls, or prove access through an external provider firewall. A final real client test is still necessary.
