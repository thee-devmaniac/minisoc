FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    mkdir -p /var/run/sshd && \
    rm -rf /var/lib/apt/lists/*

# Deliberately weak lab-only credentials — this container exists to be
# attacked from inside the isolated lab_net, never exposed elsewhere.
RUN useradd -m -s /bin/bash labuser && \
    echo "labuser:labpassword" | chpasswd && \
    echo "root:labpassword" | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

# sshd -e sends log lines (including auth failures) to stderr instead of
# syslog. We capture that stream, prepend a UTC timestamp per line (sshd -e
# output has none by itself), and append to a shared volume file that
# platform's log_tailer.py polls — same handoff pattern as capture's
# JSON-lines volume, different data source. This avoids giving platform any
# Docker-socket access just to read another container's logs.
CMD ["/bin/sh", "-c", "mkdir -p /var/log/minisoc && /usr/sbin/sshd -D -e 2>&1 | while IFS= read -r line; do printf '%s %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$line\"; done >> /var/log/minisoc/auth.log"]