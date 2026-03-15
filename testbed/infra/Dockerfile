# VULNERABILITY: Severely outdated base image with known vulnerabilities (RCE)
FROM node:8.5.0

# VULNERABILITY: Running as root
USER root

WORKDIR /app

# VULNERABILITY: Hardcoded secrets in intermediate layer (squashed but discoverable)
ENV VAULT_TOKEN="hvs.CAESIK123ABCDEFGHIJKLMNOPQRSTUVWXYZ123"

# Simulate some setup
RUN echo "Vault token: $VAULT_TOKEN" > /tmp/setup.log

# VULNERABILITY: Copying everything including sensitive local files like .env
COPY . .

# VULNERABILITY: No ENTRYPOINT / CMD isolation
CMD ["npm", "start"]
