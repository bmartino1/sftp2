FROM debian:12-slim

LABEL maintainer="bmartino1" \
      org.opencontainers.image.title="expanded-sftp-fail2ban" \
      org.opencontainers.image.description="Secure SFTP with OpenSSH + Fail2Ban (Debian slim)"

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Chicago \
    AUTO_UPDATE=suite \
    PUID=0 PGID=0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      openssh-server openssh-client openssh-sftp-server \
      fail2ban rsyslog \
      whois iptables \
      tzdata ca-certificates curl bash tini iproute2 procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# runtime dirs
RUN mkdir -p /var/run/sshd /var/run/fail2ban /config \
           /etc/fail2ban/{jail.d,filter.d,action.d} \
    && rm -f /etc/ssh/ssh_host_*key*

# defaults (seeded if user doesn't override via /config)
COPY defaults/sshd/sshd_config                     /defaults/sshd/sshd_config
COPY defaults/fail2ban/fail2ban.local              /defaults/fail2ban/fail2ban.local
COPY defaults/fail2ban/action.d/                   /defaults/fail2ban/action.d/
COPY defaults/fail2ban/filter.d/                   /defaults/fail2ban/filter.d/
COPY defaults/fail2ban/jail.d/                     /defaults/fail2ban/jail.d/

COPY entrypoint.sh      /usr/local/bin/entrypoint.sh
COPY update-inplace.sh  /usr/local/bin/update-inplace.sh
RUN chmod +x /usr/local/bin/*.sh

EXPOSE 22
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -lc 'ss -lnt | grep -q ":22 " || exit 1'

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint.sh"]
