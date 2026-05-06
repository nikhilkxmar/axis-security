FROM node:20-slim

ARG GITLEAKS_VERSION=v8.30.0
ENV NODE_ENV=production
ENV SEMGREP_VENV=/opt/semgrep-venv
ENV PATH="${SEMGREP_VENV}/bin:${PATH}"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl ca-certificates tar \
  && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv "${SEMGREP_VENV}" \
  && "${SEMGREP_VENV}/bin/pip" install --no-cache-dir --upgrade pip \
  && "${SEMGREP_VENV}/bin/pip" install --no-cache-dir semgrep \
  && semgrep --version

RUN curl -fsSL -o /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
  && tar -xzf /tmp/gitleaks.tar.gz -C /tmp \
  && mv /tmp/gitleaks /usr/local/bin/gitleaks \
  && chmod +x /usr/local/bin/gitleaks \
  && rm -rf /tmp/gitleaks.tar.gz

WORKDIR /app

COPY webhook-server/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

COPY webhook-server/ ./

RUN useradd -m -u 10001 appuser \
  && chown -R appuser:appuser /app
USER appuser

EXPOSE 3000

CMD ["node", "server.js"]

