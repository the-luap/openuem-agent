FROM golang:1.26.8-bookworm
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) emulator=qemu-system-arm; kernel=linux-image-arm64 ;; \
      amd64) emulator=qemu-system-x86; kernel=linux-image-amd64 ;; \
      *) exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends systemd busybox-static cpio gzip "$emulator" "$kernel"; \
    rm -rf /var/lib/apt/lists/*
