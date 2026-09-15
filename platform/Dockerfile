FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*
# Note: platform only ever runs `nmap -sT` (TCP connect scan), which needs no
# raw-socket capability. Do not add CAP_NET_RAW/NET_ADMIN to this container —
# that privilege stays scoped to `capture` alone (LLD §3.3, §8).

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]