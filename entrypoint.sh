#!/usr/bin/env bash
set -Eeuo pipefail

log()  { echo "[entrypoint] $*"; }
warn() { echo "[entrypoint][WARN] $*"; }
info() { echo "[info] $*"; }

umask 027

# ----- version helpers -----
ver_fail2ban()  { fail2ban-client -V 2>/dev/null | head -n1 | sed 's/[^0-9.]*\([0-9.]*\).*/\1/'; }
ver_ssh_client(){ ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([^ ]*\).*/\1/p'; }
ver_ssh_server(){ dpkg-query -W -f='${Version}\n' openssh-server 2>/dev/null || echo "unknown"; }
ver_whois()     { dpkg-query -W -f='${Version}\n' whois 2>/dev/null || echo "unknown"; }
ver_glibc()     { ldd --version 2>/dev/null | head -n1 | awk '{print $NF}'; }

print_versions() {
  local when="$1"
  info "${when}"
  info "  Fail2Ban: $(ver_fail2ban || echo unknown)"
  info "  OpenSSH client: $(ver_ssh_client || echo unknown)"
  info "  OpenSSH server: $(ver_ssh_server)"
  info "  whois: $(ver_whois)"
  info "  glibc: $(ver_glibc || echo unknown)"
}

# ----- timezone -----
if [[ -n "${TZ:-}" ]]; then
  ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime || true
  echo "$TZ" >/etc/timezone || true
fi

# ----- guaranteed /config structure -----
mkdir -p /config/fail2ban /config/userkeys /config/sshd /config/sshd/keys

# ----- default admin seeding (first-boot only) -----
DEFAULT_ADMIN="${DEFAULT_ADMIN:-true}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-password}"

if [[ ! -s /config/sshd/users.conf ]]; then
  if [[ "${DEFAULT_ADMIN,,}" == "true" ]]; then
    install -D -m 0644 /dev/stdin /config/sshd/users.conf <<EOF
# username:password[:e][:uid][:gid][:dir1,dir2,...]
# seeded on first boot — CHANGE THIS PASSWORD!
${ADMIN_USER}:${ADMIN_PASS}
EOF
    log "Seeded /config/sshd/users.conf with default admin (CHANGE THE PASSWORD)"
  else
    install -D -m 0644 /dev/stdin /config/sshd/users.conf <<'EOF'
# username:password[:e][:uid][:gid][:dir1,dir2,...]
# file created on first boot; add your users here
EOF
    log "Created empty /config/sshd/users.conf (DEFAULT_ADMIN=false)"
  fi
fi

# ----- seed defaults into /etc (only if missing) -----
seed() { local src="$1" dst="$2"; [[ -f "$dst" ]] || { install -D -m 0644 "$src" "$dst"; log "Seeded $(basename "$dst")"; }; }

seed /defaults/sshd/sshd_config            /etc/ssh/sshd_config
seed /defaults/fail2ban/fail2ban.local     /etc/fail2ban/fail2ban.local
for f in /defaults/fail2ban/jail.d/*;   do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/jail.d/$(basename "$f")"; done
for f in /defaults/fail2ban/filter.d/*; do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/filter.d/$(basename "$f")"; done
for f in /defaults/fail2ban/action.d/*; do [[ -f "$f" ]] && seed "$f" "/etc/fail2ban/action.d/$(basename "$f")"; done

# ----- merge user-provided fail2ban content from /config -----
merge_dir(){ local s="$1" d="$2"; [[ -d "$s" ]] && { cp -a "$s/." "$d/"; log "Merged $(basename "$s")"; }; }
merge_dir /config/fail2ban/jail.d    /etc/fail2ban/jail.d
merge_dir /config/fail2ban/filter.d  /etc/fail2ban/filter.d
merge_dir /config/fail2ban/action.d  /etc/fail2ban/action.d
[[ -f /config/fail2ban/fail2ban.local ]] && install -m0644 /config/fail2ban/fail2ban.local /etc/fail2ban/fail2ban.local && log "Applied fail2ban.local from /config"

# Ensure F2B log/DB files are present on persistent volume
touch /config/fail2ban/{whois.log,fail2ban.log} || true

# ----- perms for /config -----
chown -R root:root /config/sshd /config/fail2ban || true
chmod 0755 /config /config/sshd /config/fail2ban || true
find /config -type f \( -name "*.conf" -o -name "*.local" \) -exec chmod 0644 {} \; || true
find /config/sshd/keys -type f -name "*_key" -exec chmod 0600 {} \; 2>/dev/null || true
chmod 0600 /etc/ssh/sshd_config || true

# ----- print build-time versions (from image) -----
if [[ -f /opt/debug/build-versions.txt ]]; then
  info "Application versions at build step:"
  sed 's/^/[info]   /' /opt/debug/build-versions.txt
fi

# ----- print runtime versions BEFORE update -----
print_versions "Application versions at container start:"

# ----- optional updates (suite-safe by default) -----
case "${AUTO_UPDATE:-suite}" in
  none)  log "AUTO_UPDATE=none";;
  suite) log "AUTO_UPDATE=suite"; /usr/local/bin/update-inplace.sh suite || true;;
  custom)
    if [[ -x /config/updateapps.sh ]]; then
      log "AUTO_UPDATE=custom"
      /config/updateapps.sh || true
    else
      log "AUTO_UPDATE=custom but /config/updateapps.sh missing; falling back to suite"
      /usr/local/bin/update-inplace.sh suite || true
    fi
    ;;
  *) log "AUTO_UPDATE=${AUTO_UPDATE} not recognized";;
esac

# ----- print runtime versions AFTER update -----
print_versions "Application versions after update:"

# ----- host keys under /config (so they persist) -----
# ed25519
if [[ ! -f /config/sshd/keys/ssh_host_ed25519_key ]]; then
  ssh-keygen -t ed25519 -f /config/sshd/keys/ssh_host_ed25519_key -N ''
  chmod 600 /config/sshd/keys/ssh_host_ed25519_key
fi
# rsa
if [[ ! -f /config/sshd/keys/ssh_host_rsa_key ]]; then
  ssh-keygen -t rsa -b 4096 -f /config/sshd/keys/ssh_host_rsa_key -N ''
  chmod 600 /config/sshd/keys/ssh_host_rsa_key
fi

# ----- optional sshd toggles via env -----
# PASSWORD_AUTH=yes|no (default: from config)
if [[ -n "${PASSWORD_AUTH:-}" ]]; then
  if grep -qE '^[# ]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config; then
    sed -i "s/^[# ]*PasswordAuthentication[[:space:]].*/PasswordAuthentication ${PASSWORD_AUTH}/" /etc/ssh/sshd_config
  else
    printf "\nPasswordAuthentication %s\n" "${PASSWORD_AUTH}" >> /etc/ssh/sshd_config
  fi
fi

# ALLOW_USERS="user1 user2 ..."
if [[ -n "${ALLOW_USERS:-}" ]]; then
  if grep -q '^AllowUsers' /etc/ssh/sshd_config; then
    sed -i "s/^AllowUsers.*/AllowUsers ${ALLOW_USERS}/" /etc/ssh/sshd_config
  else
    printf "\nAllowUsers %s\n" "$ALLOW_USERS" >> /etc/ssh/sshd_config
  fi
fi

# ----- user management (users.conf + env + args) -----
userConfPath="/config/sshd/users.conf"
userConfFinalPath="/var/run/sftp/users.conf"
mkdir -p "$(dirname "$userConfFinalPath")"

reUser='[A-Za-z0-9._][A-Za-z0-9._-]{0,31}'
rePass='[^:]{0,255}'
reUid='[[:digit:]]*'
reGid='[[:digit:]]*'
reDir='[^:]*'
reArgs="^(${reUser})(:${rePass})(:e)?(:${reUid})?(:${reGid})?(:${reDir})?$"
reArgsMaybe='^[^:[:space:]]+:.*$'
reArgSkip='^([[:blank:]]*#.*|[[:blank:]]*)$'

startSshd=true
if [[ -n "${1:-}" && ! "$1" =~ $reArgsMaybe ]]; then
  startSshd=false
fi

> "$userConfFinalPath"
if [[ -f "$userConfPath" ]]; then
  grep -Ev "$reArgSkip" "$userConfPath" >> "$userConfFinalPath" || true
fi
if $startSshd && [[ -n "${SFTP_USERS:-}" ]]; then
  for spec in $SFTP_USERS; do echo "$spec" >> "$userConfFinalPath"; done
fi
if $startSshd && [[ -n "${*:-}" ]]; then
  for spec in "$@"; do echo "$spec" >> "$userConfFinalPath"; done
fi

create_user() {
  local line="$*"
  IFS=':' read -r username password maybe_e uid gid dirs <<<"$line"
  [[ "$username:$password" =~ ^${reUser}:${rePass}$ ]] || { warn "Bad user spec: $line"; return 0; }

  local chpasswd_opt=
  [[ "${maybe_e:-}" == "e" ]] && chpasswd_opt="-e"

  local useradd_opts=()
  [[ -n "${uid:-}" ]] && useradd_opts+=(--non-unique --uid "$uid")
  if [[ -n "${gid:-}" ]]; then
    if ! getent group "$gid" >/dev/null; then groupadd --gid "$gid" "grp_$gid"; fi
    useradd_opts+=(--gid "$gid")
  fi

  if getent passwd "$username" >/dev/null; then
    log "User $username exists; skipping useradd"
  else
    useradd "${useradd_opts[@]}" "$username"
  fi

  mkdir -p "/home/$username" "/home/$username/.ssh"
  chown root:root "/home/$username"
  chmod 755 "/home/$username"

  if [[ -n "${password:-}" ]]; then
    echo "$username:$password" | chpasswd $chpasswd_opt
  else
    usermod -p "*" "$username" || true
  fi

  local key_file="/config/userkeys/${username}.pub"
  if [[ -f "$key_file" ]]; then
    chown "$(id -u "$username")" "/home/$username/.ssh"
    chmod 700 "/home/$username/.ssh"
    install -m 0600 "$key_file" "/home/$username/.ssh/${username}.pub"
    install -m 0600 "$key_file" "/home/$username/.ssh/authorized_keys"
    chown "$(id -u "$username")" "/home/$username/.ssh/"{authorized_keys,"${username}.pub"}
    log "Installed SSH key for $username"
  fi

  if [[ -n "${dirs:-}" ]]; then
    IFS=',' read -r -a arr <<<"$dirs"
    local ugid="$(id -g "$username")"
    for sub in "${arr[@]}"; do
      [[ -z "$sub" ]] && continue
      mkdir -p "/home/$username/$sub"
      chown -R "$(id -u "$username"):$ugid" "/home/$username/$sub"
      log "Ensured /home/$username/$sub"
    done
  fi
}

if $startSshd; then
  if [[ -s "$userConfFinalPath" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ $reArgSkip ]] && continue
      create_user "$line"
    done < "$userConfFinalPath"
  else
    warn "No users provided; /config/sshd/users.conf is empty. See README for format."
  fi
fi

# Hooks
if [[ -d /config/sshd/scripts ]]; then
  for f in /config/sshd/scripts/*; do
    [[ -x "$f" ]] && { log "Running $f"; "$f"; } || [[ -e "$f" ]] && warn "Not executable: $f"
  done
fi

# Cleanup stale runtime files
rm -f /var/run/fail2ban/fail2ban.sock /var/run/sshd.pid || true
: > /var/log/auth.log   || true
touch /var/log/fail2ban.log || true

# Start services
log "Starting rsyslog";  service rsyslog start || (rsyslogd &)
log "Starting fail2ban"; service fail2ban start || (fail2ban-server -xf start &)

log "Starting sshd"
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
sshd_pid=$!

touch /var/log/auth.log /var/log/fail2ban.log
tail -F /var/log/auth.log /var/log/fail2ban.log &
tail_pid=$!

if ! $startSshd; then
  log "Executing custom command: $*"
  exec "$@"
fi

wait "$sshd_pid"
