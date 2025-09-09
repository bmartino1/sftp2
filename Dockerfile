# docker-sftp/Dockerfile
FROM debian:12-slim

LABEL maintainer="you@example.com" \
      org.opencontainers.image.title="sftp-fail2ban" \
      org.opencontainers.image.description="Secure SFTP with OpenSSH + Fail2Ban (Debian slim)" \
      org.opencontainers.image.source="https://github.com/<you>/docker-sftp"

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Chicago \
    AUTO_UPDATE=suite   \
    PUID=0 PGID=0

# Base OS + packages
# - rsyslog gives us /var/log/auth.log out of the box on Debian
# - whois for fail2ban 'logwhois' action
# - iptables/nftables: choose one; Debian uses nftables under the hood; 'iptables' is still common in actions
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      openssh-server openssh-client openssh-sftp-server \
      fail2ban \
      rsyslog \
      iptables \
      whois \
      tzdata \
      ca-certificates \
      curl \
      bash \
      tini \
      iproute2 \
      procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure runtime dirs
RUN mkdir -p /var/run/sshd /var/run/fail2ban /config \
           /etc/fail2ban/jail.d /etc/fail2ban/filter.d /etc/fail2ban/action.d \
    && rm -f /etc/ssh/ssh_host_*key*

# Copy defaults (used only if /config doesn't provide them)
COPY defaults/sshd/sshd_config                  /defaults/sshd/sshd_config
COPY defaults/fail2ban/fail2ban.local           /defaults/fail2ban/fail2ban.local
COPY defaults/fail2ban/jail.d/                  /defaults/fail2ban/jail.d/
# (Optional) rsyslog override if you want to tweak; Debian already logs auth.log
# COPY defaults/rsyslog/50-default.conf         /etc/rsyslog.d/50-default.conf

# Boot logic + updater
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY update-inplace.sh /usr/local/bin/update-inplace.sh
RUN chmod +x /usr/local/bin/*.sh

# Expose SFTP/SSH
EXPOSE 22

# Healthcheck: sshd listening?
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -lc 'ss -lnt | grep -q ":22 " || exit 1'

# Start
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint.sh"]
