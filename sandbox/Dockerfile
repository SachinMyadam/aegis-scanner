FROM node:lts-slim

# Install latest Chromium and fonts manually
# This ensures we have all necessary dependencies and a working browser binary
RUN apt-get update \
    && apt-get install -y chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Tell Puppeteer to skip downloading Chrome (use ours instead)
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

COPY package.json .
RUN npm install

COPY scan.js .

EXPOSE 3000

CMD ["node", "scan.js"]
