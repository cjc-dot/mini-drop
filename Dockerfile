FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV MINIDROP_RUNTIME=/runtime
ENV PYTHONPATH=/app/analysis:/app/drop:/app/apiserver

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bpftrace \
        ca-certificates \
        curl \
        gcc \
        libpython3.10 \
        libtraceevent1 \
        linux-tools-common \
        linux-tools-generic \
        make \
        procps \
        python3 \
        python3-pip \
        sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install -r requirements.txt

COPY analysis ./analysis
COPY apiserver ./apiserver
COPY deploy ./deploy
COPY drop ./drop
COPY scripts ./scripts
COPY tests ./tests
COPY web_frontend ./web_frontend
COPY workloads ./workloads
COPY Makefile ./

RUN mkdir -p /runtime/builds /runtime/profiles /runtime/logs /runtime/data /runtime/tmp

CMD ["python3", "-m", "minidrop_apiserver", "--host", "0.0.0.0", "--port", "8000", "--runtime-dir", "/runtime"]
