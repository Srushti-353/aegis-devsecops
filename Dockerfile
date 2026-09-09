FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tar \
    && rm -rf /var/lib/apt/lists/*

RUN git --version

RUN TRIVY_VERSION=0.74.0 \
    && ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *) echo "Unsupported Debian architecture: ${ARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz

RUN trivy --version

RUN OSV_VERSION=2.5.1 \
    && ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
        amd64|arm64) OSV_ARCH="${ARCH}" ;; \
        *) echo "Unsupported Debian architecture: ${ARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

RUN osv-scanner --version

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
