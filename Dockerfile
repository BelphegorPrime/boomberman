FROM node:22-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3000
CMD ["node", "dist/start.js"]

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}" \
      org.opencontainers.image.revision="${GITHUB_SHA}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Boomberman" \
      org.opencontainers.image.description="Threat simulation environment with honeypots and mock payloads."
