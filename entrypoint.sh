#!/usr/bin/env bash
set -Eeuo pipefail
log(){ echo "[entrypoint] $*"; }

# timezone
if [[ -n "${TZ:-}" ]]; then
  ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime || true
  echo "$TZ" >/etc/timezone || true
fi

# seed defaults
seed() { local src="$1" dst="$2"; [[ -f "$dst" ]] || install -D -m 0644 "$src" "$dst" && log "Seeded $(basename "$dst")"; }
seed /defaults/sshd/sshd_config                   /etc/ssh/sshd_config
seed /defaults/fail2ban/fail2ban.local            /etc/fail2ban/fail2ban.local
for f in /defaults/fail2ban/jail.d/*; do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/jail.d/$(basename "$f")"; done
for f in /defaults/fail2ban/filter.d/*; do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/filter.d/$(basename "$f")"; done
for f in /defaults/fail2ban/action.d/*; do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/action.d/$(basename "$f")"; done

# merge user-provided fail2ban content, if present
merge_dir(){ local s="$1" d="$2"; [[ -d "$s" ]] && cp -a "$s/." "$d/" && log "Merged $(basename "$s")"; }
merge_dir /config/fail2ban/jail.d    /etc/fail2ban/jail.d
merge_dir /config/fail2ban/filter.d  /etc/fail2ban/filter.d
merge_dir /config/fail2ban/action.d  /etc/fail2ban/action.d
[[ -f /config/fail2ban/fail2ban.local ]] && install -m0644 /config/fail2ban/fail2ban.local /etc/fail2ban/fail2ban.local && log "Applied fail2ban.local from /config"

# ensure whois log/DB dir exists (your layout)
mkdir -p /config/fail2ban
touch /config/fail2ban/{whois.log,fail2ban.log} || true

# optional updates (suite-safe)
case "${AUTO_UPDATE:-suite}" in
  none)  log "AUTO_UPDATE=none";;
  suite) log "AUTO_UPDATE=suite"; /usr/local/bin/update-inplace.sh suite || true;;
  custom) if [[ -x /config/updateapps.sh ]]; then log "AUTO_UPDATE=custom"; /config/updateapps.sh || true; else log "custom script missing; falling back to suite"; /usr/local/bin/update-inplace.sh suite || true; fi;;
  *) log "AUTO_UPDATE=${AUTO_UPDATE} not recognized";;
esac

# host keys in /config (matches your sshd_config)
mkdir -p /config/sshd/keys
[[ -f /config/sshd/keys/ssh_host_ed25519_key ]] || ssh-keygen -t ed25519 -f /config/sshd/keys/ssh_host_ed25519_key -N '' && chmod 600 /config/sshd/keys/ssh_host_ed25519_key
[[ -f /config/sshd/keys/ssh_host_rsa_key     ]] || ssh-keygen -t rsa -b 4096 -f /config/sshd/keys/ssh_host_rsa_key -N '' && chmod 600 /config/sshd/keys/ssh_host_rsa_key

# services
log "Starting rsyslog";  service rsyslog start || (rsyslogd &)
log "Starting fail2ban"; service fail2ban start || (fail2ban-server -xf start &)
log "Starting sshd";     /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
sshd_pid=$!

touch /var/log/auth.log /var/log/fail2ban.log
tail -F /var/log/auth.log /var/log/fail2ban.log &
wait $sshd_pid
