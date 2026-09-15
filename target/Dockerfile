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

CMD ["/usr/sbin/sshd", "-D", "-e"]
