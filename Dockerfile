# ---- Dockerfile (Debian 12 slim, pre-make + version stamp) ----
FROM debian:12-slim

LABEL maintainer="bmartino1" \
      org.opencontainers.image.title="expanded-sftp-fail2ban" \
      org.opencontainers.image.description="Secure SFTP with OpenSSH + Fail2Ban (Debian slim)"

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Chicago \
    AUTO_UPDATE=suite \
    PUID=0 PGID=0

# Ensure all runtime directories exist (for mounts, logs, and service compatibility)
RUN mkdir -p /etc/default/sshd \
             /etc/default/f2ban \
             /etc/fail2ban \
             /etc/fail2ban/filter.d \
             /etc/ssh \
             /etc/syslog-ng \
             /var/log \
             /var/run/sshd \
             /var/run/fail2ban
             
# Core packages installed
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      openssh-server openssh-client openssh-sftp-server \
      fail2ban rsyslog \
      whois iptables \
      tzdata ca-certificates curl bash tini iproute2 procps \
      init-system-helpers \
      net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ----- Pre-make: runtime dirs & log files with sane perms -----
# sshd wants /var/run/sshd; fail2ban wants /var/run/fail2ban
# rsyslog/Fail2Ban will write these logs; pre-touch so tail works immediately
RUN set -eux; \
    mkdir -p \
      /var/run/sshd \
      /var/run/fail2ban \
      /var/spool/rsyslog \
      /config \
      /etc/fail2ban/jail.d \
      /etc/fail2ban/filter.d \
      /etc/fail2ban/action.d \
      /defaults/sshd \
      /defaults/fail2ban/jail.d \
      /defaults/fail2ban/filter.d \
      /defaults/fail2ban/action.d; \
    rm -f /etc/ssh/ssh_host_*key*; \
    # logs & perms
    touch /var/log/auth.log /var/log/fail2ban.log; \
    chown root:adm /var/log/auth.log || true; \
    chmod 0640 /var/log/auth.log || true; \
    chmod 0644 /var/log/fail2ban.log || true; \
    chmod 0755 /etc/fail2ban /etc/fail2ban/jail.d /etc/fail2ban/filter.d /etc/fail2ban/action.d; \
    chmod 0755 /var/run/sshd /var/run/fail2ban /var/spool/rsyslog /defaults

# Make sure rsyslog will write auth logs (Debian default already does; this enforces it)
RUN printf 'auth,authpriv.*\t/var/log/auth.log\n' > /etc/rsyslog.d/00-auth.conf

# ----- Defaults (seeded at runtime if user doesn't provide /config files) -----
COPY defaults/sshd/sshd_config                     /defaults/sshd/sshd_config
COPY defaults/fail2ban/fail2ban.local              /defaults/fail2ban/fail2ban.local
COPY defaults/fail2ban/action.d/                   /defaults/fail2ban/action.d/
COPY defaults/fail2ban/filter.d/                   /defaults/fail2ban/filter.d/
COPY defaults/fail2ban/jail.d/                     /defaults/fail2ban/jail.d/

# Lock down default file modes now (keeps linters/sshd happy)
RUN set -eux; \
    find /defaults -type d -exec chmod 0755 {} \; ; \
    find /defaults -type f -exec chmod 0644 {} \; ; \
    chown -R root:root /defaults

# Entrypoint & updater
COPY entrypoint.sh      /usr/local/bin/entrypoint.sh
COPY update-inplace.sh  /usr/local/bin/update-inplace.sh
RUN chmod +x /usr/local/bin/*.sh

# Healthcheck & port
EXPOSE 22
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -lc 'ss -lnt | grep -q ":22 " || exit 1'

# ----- Build-time version stamp (what this image ships with) -----
RUN mkdir -p /opt/debug && \
    sh -lc '\
      { \
        echo "Fail2Ban: $(fail2ban-client -V 2>/dev/null | head -n1 | sed "s/[^0-9.]*\([0-9.]*\).*/\1/")"; \
        echo "OpenSSH client: $(ssh -V 2>&1 | sed -n "s/.*OpenSSH_\\([^ ]*\\).*/\\1/p")"; \
        echo "OpenSSH server: $(dpkg-query -W -f="\${Version}\n" openssh-server 2>/dev/null)"; \
        echo "whois: $(dpkg-query -W -f="\${Version}\n" whois 2>/dev/null)"; \
        echo "glibc: $(ldd --version 2>/dev/null | head -n1 | awk "{print \$NF}")"; \
        date -u +"Built at: %Y-%m-%dT%H:%M:%SZ"; \
      } > /opt/debug/build-versions.txt'

# Persist /config by default (optional but handy)
VOLUME ["/config"]

# Tini as PID 1 + entrypoint
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint.sh"]
