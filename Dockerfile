FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ARG CHECKSEC_VERSION=3.2.0
ARG CAPA_VERSION=9.4.0
ARG SYFT_VERSION=1.51.1
ARG GRYPE_VERSION=0.118.0
ARG TRIVY_VERSION=0.73.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        acl \
        attr \
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
        clamav \
        libcap2-bin \
        libxml2-utils \
        openssl \
        pax-utils \
        p7zip-full \
        python3 \
        python3-pip \
        python3-venv \
        rpm \
        sqlite3 \
        sed \
        squashfs-tools \
        tar \
        unzip \
        wget \
        xz-utils \
        zip \
        zstd \
        yara \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/install/install-release-tools.sh /tmp/install-release-tools.sh
RUN CHECKSEC_VERSION="$CHECKSEC_VERSION" \
    CAPA_VERSION="$CAPA_VERSION" \
    SYFT_VERSION="$SYFT_VERSION" \
    GRYPE_VERSION="$GRYPE_VERSION" \
    TRIVY_VERSION="$TRIVY_VERSION" \
    /tmp/install-release-tools.sh \
    && rm /tmp/install-release-tools.sh

ENV GRYPE_DB_CACHE_DIR=/workspace/cache/grype/db \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    TRIVY_CACHE_DIR=/workspace/cache/trivy \
    TRIVY_SKIP_DB_UPDATE=true \
    CLAMAV_DB_DIR=/workspace/cache/clamav

WORKDIR /workspace

CMD ["bash"]
