#WIP
#!/usr/bin/env bash
set -Eeuo pipefail
log(){ echo "[update] $*"; }

mode="${1:-suite}"

if [[ "$mode" == "suite" ]]; then
  log "Refreshing apt and upgrading pinned packages (bookworm)"
  apt-get update -y || true
  # Only upgrade within the configured Debian suite
  apt-get --option Dpkg::Options::=--force-confold \
          --no-install-recommends \
          install -y --only-upgrade \
            openssh-server openssh-client openssh-sftp-server fail2ban whois || true
  log "Versions after upgrade:"
  dpkg -l | awk '/openssh-(server|client)|fail2ban|whois/{print $1,$2,$3}'
else
  log "Unknown mode '$mode' (expected 'suite')"
fi

exit 0

