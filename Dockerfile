FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils \
        bzip2 \
        ca-certificates \
        coreutils \
        cpio \
        curl \
        file \
        findutils \
        gawk \
        git \
        grep \
        gzip \
        jq \
        p7zip-full \
        python3 \
        python3-pip \
        python3-venv \
        rpm \
        sed \
        squashfs-tools \
        tar \
        unzip \
        wget \
        xz-utils \
        zip \
        zstd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["bash"]
