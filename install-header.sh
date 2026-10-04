#!/usr/bin/env bash
set -euo pipefail
umask 077

case "${1:-}" in
  --help|-h)
    printf '%s\n' 'Backhaul Easy by alirezaw' 'Usage: bash install.sh [--check | --upgrade | --no-menu | --uninstall]' 'Run the same installer on Iran first, then Outside.' '--upgrade installs this bundled manager and verified Backhaul version, preserving configuration.'
    exit 0 ;;
  --uninstall)
    if command -v backhaul-easy >/dev/null 2>&1; then exec backhaul-easy uninstall; fi
    printf '%s\n' 'No installed manager found.' >&2; exit 1 ;;
  ''|--check|--upgrade|--no-menu) ;;
  *) printf '%s\n' 'Unknown argument. Use --help.' >&2; exit 2 ;;
esac
[[ "$EUID" -eq 0 ]] || { printf '%s\n' 'Run as root (sudo bash install.sh).' >&2; exit 1; }
[[ "$(uname -s)" == Linux && -d /run/systemd/system ]] || { printf '%s\n' 'A Linux server running systemd is required.' >&2; exit 1; }
. /etc/os-release
case "$ID:${VERSION_ID:-}" in
  ubuntu:22.04*|ubuntu:24.04*|ubuntu:26.04*|debian:12|debian:13) ;;
  *) printf '%s\n' 'Supported: Ubuntu 22.04/24.04/26.04 LTS (including point releases), Debian 12/13.' >&2; exit 1 ;;
esac
case "$(uname -m)" in x86_64|aarch64) ;; *) printf '%s\n' 'Supported architectures: amd64, arm64.' >&2; exit 1 ;; esac

missing=0
for tool in python3 curl openssl ss; do command -v "$tool" >/dev/null 2>&1 || missing=1; done
[[ -f /etc/ssl/certs/ca-certificates.crt ]] || missing=1
if [[ "$missing" == 1 ]]; then
  if [[ "${1:-}" == --check ]]; then printf '%s\n' 'Install prerequisites first: apt-get update && apt-get install -y python3 curl ca-certificates openssl iproute2'; exit 1; fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl ca-certificates openssl iproute2
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
