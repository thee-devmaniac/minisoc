FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir scapy==2.6.0

COPY sniffer.py .

CMD ["python", "sniffer.py"]
