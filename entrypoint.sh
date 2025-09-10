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
shopt -s nullglob

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
  /config/debug/ /config/log/ /config/fail2ban /config/userkeys /config/sshd /config/sshd/keys \
  /config/fail2ban/{jail.d,filter.d,action.d} \
  /etc/ssh \
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
${ADMIN_USER}:${ADMIN_PASS}:1000:100
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

# ===== ensure base config presence (first boot) =====
if [[ ! -e /config/fail2ban/fail2ban.local ]]; then
  log "fail2ban.local missing from /config — restoring from /defaults"
  cp /defaults/fail2ban/fail2ban.local /config/fail2ban/fail2ban.local
else
  log "Using existing /config/fail2ban/fail2ban.local"
fi

if [[ ! -e /config/fail2ban/jail.local ]]; then
  log "jail.local missing from /config — restoring from /defaults"
  cp /defaults/fail2ban/jail.local /config/fail2ban/jail.local
else
  log "Using existing /config/fail2ban/jail.local"
fi

if [[ ! -e /config/sshd/sshd_config ]]; then
  log "sshd_config missing from /config — restoring from /defaults"
  cp /defaults/sshd/sshd_config /config/sshd/sshd_config
else
  log "Using existing /config/sshd/sshd_config"
fi

# --- Permissions (conservative) ---
log "Setting ownership and permissions on /config"
chown -R root:root /config/fail2ban /config/sshd
chmod -R 755 /config
for f in /config/fail2ban/*.local /config/sshd/*.conf /config/sshd/users.conf; do
  [[ -e "$f" ]] && chmod 644 "$f"
done
chmod 600 /config/sshd/keys/*_key 2>/dev/null || true
chmod 600 /config/userkeys/*_key 2>/dev/null || true

# --- Apply active configs (idempotent) ---
smart_copy() {
  local src="$1" dst="$2"
  mkdir -p "$(dirname "$dst")"
  if [[ -e "$dst" ]]; then
    local rs rd
    rs="$(readlink -f "$src" || echo "$src")"
    rd="$(readlink -f "$dst" || echo "$dst")"
    if [[ "$rs" == "$rd" ]]; then info "Skip copy: $dst already points to $src"; return 0; fi
    if cmp -s "$src" "$dst"; then info "Skip copy: $dst already has same content"; return 0; fi
  fi
  install -D -m 0644 "$src" "$dst"
}

smart_copy /config/sshd/sshd_config        /etc/ssh/sshd_config
smart_copy /config/fail2ban/fail2ban.local /etc/fail2ban/fail2ban.local
smart_copy /config/fail2ban/jail.local     /etc/fail2ban/jail.d/jail.local

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
  local prefer="$1" fallback="$2" dest="$3" src=
  if   [[ -d "$prefer"  ]]; then src="$prefer"
  elif [[ -d "$fallback" ]]; then src="$fallback"
  else warn "No packaged directory for $(basename "$dest")"; return 0; fi
  find "$src" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null | \
    xargs -0 -I{} bash -c 'd="$0/$(basename "$1")"; [[ -f "$d" ]] || install -D -m0644 "$1" "$d"' "$dest" {}
  log "Ensured $(basename "$dest") from $src"
}

copy_pkg_root_noclobber() {
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
  if [[ -L "$target" ]]; then ln -sfn "$src" "$target"; return 0; fi
  if [[ -e "$target" ]]; then
    if [[ ! -e "${target}.bak.original" ]]; then
      mv "$target" "${target}.bak.original"; log "Backed up $target -> ${target}.bak.original"
    else
      rm -rf "${target}.bak" 2>/dev/null || true
      mv "$target" "${target}.bak"; log "Rotated $target -> ${target}.bak"
    fi
  fi
  ln -sfn "$src" "$target"
}

# ===== seed defaults to /config (first boot only; no clobber) =====
[[ -f /config/sshd/sshd_config ]] || seed_default /defaults/sshd/sshd_config /config/sshd/sshd_config
seed_default /defaults/fail2ban/fail2ban.local /config/fail2ban/fail2ban.local
seed_default /defaults/fail2ban/jail.local     /config/fail2ban/jail.local
for f in /defaults/fail2ban/jail.d/*;   do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/jail.d/$(basename "$f")";   done
for f in /defaults/fail2ban/filter.d/*; do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/filter.d/$(basename "$f")"; done
for f in /defaults/fail2ban/action.d/*; do [[ -f "$f" ]] && seed_default "$f" "/config/fail2ban/action.d/$(basename "$f")"; done

# ===== ensure packaged base files land in /config =====
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
      backup_and_link /etc/fail2ban/jail.local     /config/fail2ban/jail.local
      backup_and_link /etc/fail2ban/jail.conf      /config/fail2ban/jail.conf
      backup_and_link /etc/fail2ban/jail.d         /config/fail2ban/jail.d
      backup_and_link /etc/fail2ban/filter.d       /config/fail2ban/filter.d
      backup_and_link /etc/fail2ban/action.d       /config/fail2ban/action.d
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

# ===== log files: create if missing (do NOT truncate) =====
mkdir -p /config/log
ensure_log() { local f="$1"; [[ -e "$f" ]] || install -D -m 0644 /dev/null "$f"; }
ensure_log /config/log/auth.log
ensure_log /config/log/fail2ban.log
ensure_log /config/log/whois.log

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
    local ugid
    ugid="$(id -g "$username")"
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

# ===== cleanup & legacy logs =====
rm -f /var/run/fail2ban/fail2ban.sock /var/run/sshd.pid || true
# Do NOT truncate logs here.

# ===== optional preflight =====
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client -d > /config/debug/fail2ban-dryrun.log 2>&1 || true
fi

# ===== normalize sshd logging lines =====
# Keep only ONE Subsystem sftp line, enforce -f AUTHPRIV -l INFO
sed -i -E '/^[[:space:]]*Subsystem[[:space:]]+sftp[[:space:]]/d' /etc/ssh/sshd_config
printf '\nSubsystem sftp internal-sftp -f AUTHPRIV -l INFO\n' >> /etc/ssh/sshd_config
# Enforce SyslogFacility AUTHPRIV and LogLevel VERBOSE
if grep -qE '^[# ]*SyslogFacility[[:space:]]+' /etc/ssh/sshd_config; then
  sed -i 's/^[# ]*SyslogFacility[[:space:]].*/SyslogFacility AUTHPRIV/' /etc/ssh/sshd_config
else
  printf 'SyslogFacility AUTHPRIV\n' >> /etc/ssh/sshd_config
fi
if grep -qE '^[# ]*LogLevel[[:space:]]+' /etc/ssh/sshd_config; then
  sed -i 's/^[# ]*LogLevel[[:space:]].*/LogLevel VERBOSE/' /etc/ssh/sshd_config
else
  printf 'LogLevel VERBOSE\n' >> /etc/ssh/sshd_config
fi

# Warn if still multiple Subsystem lines (paranoia)
if [[ "$(grep -E '^[[:space:]]*Subsystem[[:space:]]+sftp' -c /etc/ssh/sshd_config || echo 0)" -gt 1 ]]; then
  warn "Multiple 'Subsystem sftp' lines remain — please check /config/sshd/sshd_config"
fi

# Validate sshd config before starting
if ! sshd -t -f /etc/ssh/sshd_config 2> /config/debug/sshd-config-check.err; then
  warn "sshd config check failed:"
  sed 's/^/[sshd-check] /' /config/debug/sshd-config-check.err || true
  exit 1
fi

# ===== build-time seeding mode =====
if [[ "${MODE:-start}" == "seed" ]]; then
  log "MODE=seed: completed config/seed/update; not starting daemons"
  exit 0
fi

# ===== start daemons =====
# Ensure rsyslog routes AUTH/AUTHPRIV to persisted auth log
printf 'auth,authpriv.*\t/config/log/auth.log\n' > /etc/rsyslog.d/00-auth.conf

if command -v rsyslogd >/dev/null 2>&1; then
  log "Starting rsyslogd…"
  rsyslogd || warn "rsyslogd failed to start"
else
  warn "rsyslogd not installed"
fi

# Make sure Debian's maily default can't sneak back in:
# Provide a last-word override file that disables mail macros.
mkdir -p /etc/fail2ban/jail.d
cat >/etc/fail2ban/jail.d/zz-nomail.local <<'EOF'
[DEFAULT]
action_mw  = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="tcp"]
action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="tcp"]
EOF

if command -v fail2ban-client >/dev/null 2>&1; then
  log "Starting fail2ban via client…"
  fail2ban-client -x start || warn "fail2ban-client start failed"
elif command -v fail2ban-server >/dev/null 2>&1; then
  log "Starting fail2ban via server (detached)…"
  fail2ban-server -x start >/var/log/f2b.start.log 2>&1 &
else
  warn "fail2ban not installed"
fi

# ===== mirror key logs to Docker stdout (toggle with TAIL_LOGS=false) =====
case "${TAIL_LOGS:-true}" in
  1|true|yes|on|TRUE|YES|ON)
    ( tail -n+1 -q -F /config/log/auth.log /config/log/fail2ban.log /config/log/whois.log 2>/dev/null & )
    ;;
esac

# ===== final: start sshd in foreground (NO -e; logs → syslog AUTHPRIV) =====
mkdir -p /var/run/sshd
chmod 755 /var/run/sshd || true
log "Starting sshd"
exec /usr/sbin/sshd -D -f /etc/ssh/sshd_config
