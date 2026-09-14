FROM golang:1.26.8-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils debsig-verify dpkg-dev gnupg rpm systemd \
    && rm -rf /var/lib/apt/lists/*
