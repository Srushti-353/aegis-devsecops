FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tar \
    && TRIVY_VERSION=0.74.0 \
    && OSV_VERSION=2.5.1 \
    && case "${TARGETARCH}" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
         esac \
     && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
     && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" -o /tmp/trivy_checksums.txt \
     && cd /tmp \
     && grep "trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz$" trivy_checksums.txt | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${TARGETARCH}" -o /usr/local/bin/osv-scanner \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_SHA256SUMS" -o /tmp/osv-scanner_SHA256SUMS \
    && cd /usr/local/bin \
    && grep "osv-scanner_linux_${TARGETARCH}$" /tmp/osv-scanner_SHA256SUMS | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner \
    && git --version \
    && trivy --version \
    && osv-scanner --version \
    && rm -rf /tmp/trivy.tar.gz /tmp/trivy_checksums.txt /tmp/osv-scanner_SHA256SUMS /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
