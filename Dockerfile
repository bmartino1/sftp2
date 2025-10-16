# ---- Dockerfile (Debian 13 slim, pre-make + version stamp) ----
FROM debian:trixie-slim

LABEL maintainer="bmartino1" \
      org.opencontainers.image.title="sftp-fail2ban" \
      org.opencontainers.image.description="Secure SFTP with OpenSSH + Fail2Ban (Debian slim)"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Chicago \
    AUTO_UPDATE=suite \
    PUID=0 \
    PGID=0

# Create a few dirs early so later COPYs never fail
RUN mkdir -p \
      /etc/default/sshd \
      /etc/default/f2ban \
      /etc/fail2ban \
      /etc/fail2ban/filter.d \
      /etc/fail2ban/jail.d \
      /etc/ssh \
      /var/log \
      /var/run/sshd \
      /var/run/fail2ban

# Core packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      openssh-server openssh-client openssh-sftp-server \
      fail2ban rsyslog \
      whois iptables nftables \
      tzdata ca-certificates curl bash tini iproute2 procps \
      init-system-helpers net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ----- Pre-make: runtime dirs & log files with sane perms -----
RUN set -eux; \
    mkdir -p \
      /var/run/sshd \
      /var/run/fail2ban \
      /var/spool/rsyslog \
      /config \
      /defaults/sshd \
      /defaults/fail2ban/jail.d \
      /defaults/fail2ban/filter.d \
      /defaults/fail2ban/action.d; \
    rm -f /etc/ssh/ssh_host_*key*; \
    touch /var/log/auth.log /var/log/fail2ban.log; \
    chown root:adm /var/log/auth.log || true; \
    chmod 0640 /var/log/auth.log || true; \
    chmod 0644 /var/log/fail2ban.log || true; \
    chmod 0755 /var/run/sshd /var/run/fail2ban /var/spool/rsyslog /defaults

# Ensure auth logs land in /config/log/auth.log (persisted)
RUN mkdir -p /config/log && \
    printf 'auth,authpriv.*\t/config/log/auth.log\n' > /etc/rsyslog.d/00-auth.conf

# --- Build-time rsyslog tweak + validation log ---
# Disable imklog (no /proc/kmsg in containers) and validate the rsyslog config now.
RUN set -eux; \
    if grep -q 'module(load="imklog"' /etc/rsyslog.conf 2>/dev/null; then \
      sed -i -E 's/^\s*module\(load="imklog".*\)/# disabled in container: &/' /etc/rsyslog.conf || true; \
    fi; \
    mkdir -p /opt/debug; \
    rsyslogd -N1 > /opt/debug/rsyslog-buildcheck.txt 2>&1 || true

# ----- Defaults (seeded at runtime if user doesn't provide /config files) -----
COPY defaults/sshd/sshd_config                     /defaults/sshd/sshd_config
COPY defaults/sshd/users.conf                      /defaults/sshd/users.conf
COPY defaults/fail2ban/fail2ban.local              /defaults/fail2ban/fail2ban.local
COPY defaults/fail2ban/jail.local                  /defaults/fail2ban/jail.local
COPY defaults/fail2ban/action.d/                   /defaults/fail2ban/action.d/
COPY defaults/fail2ban/filter.d/                   /defaults/fail2ban/filter.d/
COPY defaults/fail2ban/jail.d/                     /defaults/fail2ban/jail.d/

# Lock down default file modes
RUN set -eux; \
    find /defaults -type d -exec chmod 0755 {} \; ; \
    find /defaults -type f -exec chmod 0644 {} \; ; \
    chown -R root:root /defaults

# Entrypoint & updater
COPY entrypoint.sh      /usr/local/bin/entrypoint.sh
COPY update-inplace.sh  /usr/local/bin/update-inplace.sh
COPY clear-log.sh  /usr/local/bin/clear-log.sh
RUN chmod +x /usr/local/bin/*.sh

# Healthcheck & port
EXPOSE 22
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -lc 'ss -lnt | grep -q ":22 " || exit 1'

# ----- Build-time version stamp (what this image ships with) -----
RUN mkdir -p /opt/debug && \
    bash -lc '\
      { \
        echo "Fail2Ban: $(fail2ban-client -V 2>/dev/null | head -n1 | sed '\''s/[^0-9.]*\([0-9.]*\).*/\1/'\'')"; \
        echo "OpenSSH client: $(ssh -V 2>&1 | sed -n '\''s/.*OpenSSH_\([^ ]*\).*/\1/p'\'')"; \
        echo "OpenSSH server: $(dpkg-query -W -f='\''${Version}\n'\'' openssh-server 2>/dev/null)"; \
        echo "rsyslog: $(dpkg-query -W -f='\''${Version}\n'\'' rsyslog 2>/dev/null)"; \
        echo "whois: $(dpkg-query -W -f='\''${Version}\n'\'' whois 2>/dev/null)"; \
        echo "glibc: $(ldd --version 2>/dev/null | head -n1 | awk '\''{print $NF}'\'')"; \
        date -u +"Built at: %Y-%m-%dT%H:%M:%SZ"; \
      } > /opt/debug/build-versions.txt'

# Persist /config by default
VOLUME ["/config"]

# Tini as PID 1 + entrypoint
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint.sh"]
