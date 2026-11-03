FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
ENV TZ=Africa/Johannesburg
RUN apk add --no-cache tzdata
# Runs as uid 1000: make /var/log/wifi-portal and /var/lib/wifi-portal on the host writable by it.
USER node
CMD ["node", "src/server.js", "/etc/wifi-portal/config.json"]
