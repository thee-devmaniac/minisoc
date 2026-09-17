#!/bin/bash
# Milestone 5: real usage, replacing the earlier placeholder.
# Runs hydra against target's SSH service with a small local wordlist of
# deliberately wrong passwords, generating real "Failed password" lines in
# target's auth log for brute_force_v1 to detect.
set -euo pipefail
echo "[run_bruteforce] running hydra against target:22"
hydra -l labuser -P /scripts/wordlist.txt -t 4 ssh://target