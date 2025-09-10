#!/usr/bin/env bash
set -Eeuo pipefail

# ===== tracing (enable with -e TRACE=1) =====
if [[ "${TRACE:-0}" == "1" ]]; then
  export PS4='+ [${BASH_SOURCE##*/}:${LINENO}] ${FUNCNAME[0]:-main}: '
  set -x
fi
trap 'rc=$?; echo "[entrypoint][ERR] exit $rc at line $LINENO running: ${BASH_COMMAND}"; exit $rc' ERR

log()  { echo "[entrypoint] $*"; }
warn() { echo "[entrypoint][WARN] $*"; }
info() { echo "[info] $*"; }

umask 027

# ===== version helpers =====
ver_fail2ban()  { command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client -V 2>/dev/null | head -n1 | sed 's/[^0-9.]*\([0-9.]*\).*/\1/' || echo "unknown"; }
ver_ssh_client(){ command -v ssh >/dev/null 2>&1 && ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([^ ]*\).*/\1/p' || echo "unknown"; }
ver_ssh_server(){ dpkg-query -W -f='${Version}\n' openssh-server 2>/dev/null || echo "unknown"; }
ver_whois()     { dpkg-query -W -f='${Version}\n' whois 2>/dev/null || echo "unknown"; }
ver_glibc()     { ldd --version 2>/dev/null | head -n1 | awk '{print $NF}' || echo "unknown"; }

print_versions() {
  local when="$1"
  info "${when}"
  info "  Fail2Ban:       $(ver_fail2ban)"
  info "  OpenSSH client: $(ver_ssh_client)"
  info "  OpenSSH server: $(ver_ssh_server)"
  info "  whois:          $(ver_whois)"
  info "  glibc:          $(ver_glibc)"
}

# ===== timezone =====
if [[ -n "${TZ:-}" && -e "/usr/share/zoneinfo/${TZ}" ]]; then
  ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime || true
  echo "$TZ" >/etc/timezone || true
fi

# ===== required dirs =====
mkdir -p \
  /config/fail2ban /config/userkeys /config/sshd /config/sshd/keys \
  /config/fail2ban/{jail.d,filter.d,action.d} \
  /etc/fail2ban /etc/fail2ban/{jail.d,filter.d,action.d} \
  /var/run/sshd /var/run/fail2ban /var/log /opt/debug

# ===== default admin (first boot) =====
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

# ===== rsyslog: disable imklog noise in containers =====
if [[ "${DISABLE_IMKLOG:-true}" == "true" ]]; then
  if grep -q 'module(load="imklog"' /etc/rsyslog.conf 2>/dev/null; then
    sed -i -E 's/^\s*module\(load="imklog".*\)/# disabled in container: &/' /etc/rsyslog.conf || true
    log "Disabled rsyslog imklog module (no /proc/kmsg in containers)"
  fi
fi

# ===== helpers =====
seed_default() { local src="$1" dst="$2"; [[ -f "$dst" ]] || install -D -m0644 "$src" "$dst"; }

copy_pkg_dir_noclobber() {
  # copy all *.conf from $1 (prefer) or $2 (fallback) into $3 (dest) without overwriting
  local prefer="$1" fallback="$2" dest="$3" src=
  if   [[ -d "$prefer"  ]]; then src="$prefer"
  elif [[ -d "$fallback" ]]; then src="$fallback"
  else warn "No packaged directory for $(basename "$dest")"; return 0; fi
  find "$src" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null | \
    xargs -0 -I{} bash -c 'dst="$0/$(basename "$1")"; [[ -f "$dst" ]] || install -D -m0644 "$1" "$dst"' "$dest" {}
  log "Ensured $(basename "$dest") from $src"
}

copy_pkg_root_noclobber() {
  # copy selected root-level packaged *.conf (jail.conf, paths-*.conf) into /config/fail2ban
  local dest="/config/fail2ban"
  for f in /etc/fail2ban/jail.conf /etc/fail2ban/paths*.conf /usr/share/fail2ban/paths*.conf; do
    [[ -f "$f" ]] || continue
    local d="$dest/$(basename "$f")"
    [[ -f "$d" ]] || install -D -m0644 "$f" "$d"
  done
  log "Ensured root-level Fail2Ban base (jail.conf, paths-*.conf)"
}

backup_and_link() {
  local target="$1" src="$2"
  if [[ -L "$target" ]]; then
    ln -sfn "$src" "$target"; return 0
  fi
  if [[ -e "$target" ]]; then
    if [[ ! -e "${target}.bak.original" ]]; then
      mv "$target" "${target}.bak.original"
      log "Backed up $target -> ${target}.bak.original"
    else
      rm -rf "${target}.bak" 2>/dev/null || true
      mv "$target" "${target}.bak"
      log "Rotated $target -> ${target}.bak"
    fi
  fi
  ln -sfn "$src" "$target"
}

# ===== seed defaults to /config (first boot only; no clobber) =====
[[ -f /config/sshd/sshd_config ]] || seed_default /defaults/sshd/sshd_config /config/sshd/sshd_config
seed_default /defaults/fail2ban/fail2ban.local /config/fail2ban/fail2ban.local
for f in /defaults/fail2ban/jail.d/*   ; do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/jail.d/$(basename "$f")"; done
for f in /defaults/fail2ban/filter.d/* ; do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/filter.d/$(basename "$f")"; done
for f in /defaults/fail2ban/action.d/* ; do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/action.d/$(basename "$f")"; done

# ===== ensure PACKAGED base files land in /config (no overwrite) =====
copy_pkg_dir_noclobber /usr/share/fail2ban/filter.d  /etc/fail2ban/filter.d  /config/fail2ban/filter.d
copy_pkg_dir_noclobber /usr/share/fail2ban/action.d  /etc/fail2ban/action.d  /config/fail2ban/action.d
copy_pkg_root_noclobber

# ===== auto-switch to nftables if iptables is absent =====
if ! command -v iptables >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
  if [[ ! -f /config/fail2ban/jail.d/99-banaction.local ]]; then
    cat >/config/fail2ban/jail.d/99-banaction.local <<'EOF'
[DEFAULT]
banaction = nftables-multiport
EOF
    log "Selected nftables-multiport (iptables not found)"
  fi
fi

# ===== wire configs =====
F2B_CONFIG_MODE="${F2B_CONFIG_MODE:-symlink}"
F2B_CONFIG_MODE="${F2B_CONFIG_MODE,,}"

wire_fail2ban_config() {
  case "$1" in
    symlink)
      backup_and_link /etc/fail2ban/fail2ban.local /config/fail2ban/fail2ban.local
      backup_and_link /etc/fail2ban/jail.conf      /config/fail2ban/jail.conf
      backup_and_link /etc/fail2ban/jail.d         /config/fail2ban/jail.d
      backup_and_link /etc/fail2ban/filter.d       /config/fail2ban/filter.d
      backup_and_link /etc/fail2ban/action.d       /config/fail2ban/action.d
      # paths*.conf are read from /etc — link them too
      for p in /config/fail2ban/paths*.conf; do
        [[ -f "$p" ]] && backup_and_link "/etc/fail2ban/$(basename "$p")" "$p"
      done
      log "Fail2Ban config mode=symlink (source of truth: /config/fail2ban)"
      ;;
    overlay)
      cp -a  /defaults/fail2ban/. /etc/fail2ban/
      cp -a  /config/fail2ban/.   /etc/fail2ban/
      log "Fail2Ban config mode=overlay (user files over defaults in /etc)"
      ;;
    noclobber)
      cp -a  /defaults/fail2ban/. /etc/fail2ban/
      cp -an /config/fail2ban/.   /etc/fail2ban/ || true
      log "Fail2Ban config mode=noclobber (defaults kept; override via 99-*.conf)"
      ;;
    replace)
      cp -a  /config/fail2ban/.   /etc/fail2ban/
      log "Fail2Ban config mode=replace (/etc uses only /config)"
      ;;
    *)
      warn "Unknown F2B_CONFIG_MODE='$1', falling back to symlink"
      wire_fail2ban_config "symlink"
      ;;
  esac
}
wire_fail2ban_config "$F2B_CONFIG_MODE"

# Sanity: critical files visible in /etc now
for must in \
  /etc/fail2ban/jail.conf \
  /etc/fail2ban/filter.d/common.conf \
  /etc/fail2ban/filter.d/sshd.conf \
  /etc/fail2ban/action.d/iptables-multiport.conf \
  /etc/fail2ban/action.d/nftables-multiport.conf
do
  [[ -f "$must" ]] || log "Note: missing $must (ok if unused); check seeding."
done

# ===== SSHD config persisted in /config =====
backup_and_link /etc/ssh/sshd_config /config/sshd/sshd_config

# ===== ensure logs =====
touch /config/fail2ban/{whois.log,fail2ban.log} /var/log/auth.log /var/log/fail2ban.log || true

# ===== perms =====
chown -R root:root /config/sshd /config/fail2ban || true
chmod 0755 /config /config/sshd /config/fail2ban || true
find /config -type f \( -name "*.conf" -o -name "*.local" \) -exec chmod 0644 {} \; || true
find /config/sshd/keys -type f -name "*_key" -exec chmod 0600 {} \; 2>/dev/null || true
chmod 0600 /etc/ssh/sshd_config || true

# ===== version banners =====
[[ -f /opt/debug/build-versions.txt ]] && { info "Application versions at build step:"; sed 's/^/[info]   /' /opt/debug/build-versions.txt; }
print_versions "Application versions at container start:"

# ===== updates (default NONE) =====
mode="${AUTO_UPDATE:-none}"; mode="${mode,,}"
case "$mode" in
  none|false|0|off|'') log "AUTO_UPDATE=none (updates disabled)";;
  suite|true|1|on)
    log "AUTO_UPDATE=suite"
    if [[ -x /usr/local/bin/update-inplace.sh ]]; then
      /usr/local/bin/update-inplace.sh suite || warn "update-inplace suite failed (continuing)"
    else
      warn "update-inplace.sh missing; skipping updates"
    fi
    ;;
  custom)
    if [[ -x /config/updateapps.sh ]]; then
      log "AUTO_UPDATE=custom: running /config/updateapps.sh"
      /config/updateapps.sh || warn "custom update failed (continuing)"
    else
      warn "AUTO_UPDATE=custom set but /config/updateapps.sh missing; skipping"
    fi
    ;;
  *) warn "AUTO_UPDATE='$mode' not recognized; skipping";;
esac

print_versions "Application versions after update:"

# ===== SSH host keys (persist) + link to /etc/ssh =====
[[ -f /config/sshd/keys/ssh_host_ed25519_key ]] || { ssh-keygen -t ed25519 -f /config/sshd/keys/ssh_host_ed25519_key -N ''; }
[[ -f /config/sshd/keys/ssh_host_rsa_key     ]] || { ssh-keygen -t rsa -b 4096 -f /config/sshd/keys/ssh_host_rsa_key -N ''; }
chmod 600 /config/sshd/keys/ssh_host_*_key
ln -sfn /config/sshd/keys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
ln -sfn /config/sshd/keys/ssh_host_rsa_key     /etc/ssh/ssh_host_rsa_key
chmod 600 /etc/ssh/ssh_host_*_key

# ===== optional sshd toggles =====
if [[ -n "${PASSWORD_AUTH:-}" ]]; then
  if grep -qE '^[# ]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config; then
    sed -i "s/^[# ]*PasswordAuthentication[[:space:]].*/PasswordAuthentication ${PASSWORD_AUTH}/" /etc/ssh/sshd_config
  else
    printf "\nPasswordAuthentication %s\n" "${PASSWORD_AUTH}" >> /etc/ssh/sshd_config
  fi
fi
[[ -n "${ALLOW_USERS:-}" ]] && { grep -q '^AllowUsers' /etc/ssh/sshd_config && sed -i "s/^AllowUsers.*/AllowUsers ${ALLOW_USERS}/" /etc/ssh/sshd_config || printf "\nAllowUsers %s\n" "$ALLOW_USERS" >> /etc/ssh/sshd_config; }

# ===== users =====
userConfPath="/config/sshd/users.conf"
userConfFinalPath="/var/run/sftp/users.conf"
mkdir -p "$(dirname "$userConfFinalPath")"

reUser='[A-Za-z0-9._][A-Za-z0-9._-]{0,31}'
rePass='[^:]{0,255}'
reUid='[[:digit:]]*'
reGid='[[:digit:]]*'
reDir='[^:]*'
reArgsMaybe='^[^:[:space:]]+:.*$'
reArgSkip='^([[:blank:]]*#.*|[[:blank:]]*)$'

startSshd=true
if [[ -n "${1:-}" && ! "$1" =~ $reArgsMaybe ]]; then
  startSshd=false
fi

: > "$userConfFinalPath"
[[ -f "$userConfPath" ]] && grep -Ev "$reArgSkip" "$userConfPath" >> "$userConfFinalPath" || true
if $startSshd; then
  [[ -n "${SFTP_USERS:-}" ]] && for spec in $SFTP_USERS; do echo "$spec" >> "$userConfFinalPath"; done
  [[ -n "${*:-}"         ]] && for spec in "$@";       do echo "$spec" >> "$userConfFinalPath"; done
fi

create_user() {
  local line="$*"
  IFS=':' read -r username password maybe_e uid gid dirs <<<"$line"
  [[ "$username" =~ ^$reUser$ && "$password" =~ ^$rePass$ ]] || { warn "Bad user spec: $line"; return 0; }

  local chpasswd_opt=
  [[ "${maybe_e:-}" == "e" ]] && chpasswd_opt="-e"

  local useradd_opts=()
  [[ -n "${uid:-}" ]] && useradd_opts+=(--non-unique --uid "$uid")
  if [[ -n "${gid:-}" ]]; then
    getent group "$gid" >/dev/null || groupadd --gid "$gid" "grp_$gid"
    useradd_opts+=(--gid "$gid")
  fi

  if getent passwd "$username" >/dev/null; then
    log "User $username exists; skipping useradd"
  else
    useradd "${useradd_opts[@]}" "$username"
  fi

  mkdir -p "/home/$username/.ssh"
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

# ===== hooks =====
if [[ -d /config/sshd/scripts ]]; then
  for f in /config/sshd/scripts/*; do
    [[ -x "$f" ]] && { log "Running $f"; "$f"; } || [[ -e "$f" ]] && warn "Not executable: $f"
  done
fi

# ===== cleanup & logs =====
rm -f /var/run/fail2ban/fail2ban.sock /var/run/sshd.pid || true
: > /var/log/auth.log       || true
: > /var/log/fail2ban.log   || true

# ===== optional preflight =====
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client -d > /opt/debug/fail2ban-dryrun.log 2>&1 || true
fi

# ===== build-time seeding mode =====
if [[ "${MODE:-start}" == "seed" ]]; then
  log "MODE=seed: completed config/seed/update; not starting daemons"
  exit 0
fi

# ===== start daemons =====
if command -v rsyslogd >/dev/null 2>&1; then
  log "Starting rsyslogd…"
  rsyslogd || warn "rsyslogd failed to start"
else
  warn "rsyslogd not installed"
fi

if command -v fail2ban-server >/dev/null 2>&1; then
  log "Starting fail2ban…"
  fail2ban-server -xf start || warn "fail2ban-server failed to start"
else
  warn "fail2ban-server not installed"
fi

log "Starting sshd (foreground)…"
exec /usr/sbin/sshd -e -D -f /etc/ssh/sshd_config
