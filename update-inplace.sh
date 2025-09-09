#!/usr/bin/env bash
set -Eeuo pipefail
log(){ echo "[update] $*"; }

case "${1:-suite}" in
  suite)
    log "Apt refresh + only-upgrade within Debian suite"
    apt-get update -y || true
    apt-get --option Dpkg::Options::=--force-confold \
            --no-install-recommends \
            install -y --only-upgrade \
              openssh-server openssh-client openssh-sftp-server \
              fail2ban whois || true
    log "After upgrade:"; dpkg -l | awk '/openssh-(server|client)|fail2ban|whois/{printf "%s %s %s\n",$1,$2,$3}'
    ;;
  *) log "Unknown mode";;
esac
