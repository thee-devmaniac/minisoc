FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap hydra iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
COPY scripts/ .
RUN chmod +x *.sh

# No CMD/ENTRYPOINT running attacks automatically.
# Runs are always deliberate: docker compose run attacker ./run_portscan.sh
CMD ["/bin/bash"]
