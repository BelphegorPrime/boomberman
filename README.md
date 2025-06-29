# Boomberman

A honeypot and simulated payload server for safe security testing and intrusion detection.

> **Purpose**: Boomberman simulates malicious activity to attract, detect, and study automated attacks. It includes honeypot endpoints, fake payloads, rate limiting, and AI-powered fake response generation.

---

## 🧪 Features

- **Fake ZIP/GZIP bombs** *(non-malicious, safe for testing)*
- **Tarpit** middleware to delay suspicious requests
- **Honeypot endpoints** that simulate vulnerable tools or pages
- **Captcha endpoint** to trap automated scripts
- **AI-generated fake responses** powered by [Ollama](https://ollama.com/)
- **Hourly background generation** of fake logs/responses
- **Access, event, and threat logging**
- **Webhook support** for real-time alerting
- **Metrics endpoint** for monitoring hits

---

## ⚙️ Installation

### 1. Native (Node.js)

```bash
npm install
npm run dev
````

### 2. Docker

```bash
docker build -t boomberman .
docker run -p 3000:3000 boomberman
```

### 3. Docker Compose

```bash
docker compose up --build
```

---

## 🧠 AI Integration

Boomberman can generate fake payload responses using local AI models.

Enable this feature in `.env`:

```env
ENABLE_AI_FAKE_RESPONSES=true
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

The server will automatically:

* Periodically generate and cache fake responses using the AI
* Serve corrupted or misleading payloads to attackers via honeypots

---

## 🌐 Routes

| Endpoint             | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `/files/*`           | Serves fake files or simulated ZIP bombs                        |
| `/honeypots/*`       | Triggers honeypot logic + threat logging                        |
| `/captcha`           | Forces CAPTCHA delay to trap bots                               |
| `/?tools=tarpit,...` | Enables dynamic tool triggers (`tarpit`, `honeypot`, `captcha`) |
| `/metrics`           | Returns basic hit metrics from the tarpit system                |

---

## 📦 Data Paths & Logs

Configure in `.env`:

```env
TARPIT_FILE_PATH=/data/tarpitAccess.json
BAN_FILE_PATH=/data/banned.json
EVENT_LOG_PATH=/data/events.log
AI_FAKE_RESPONSES_PATH=/data/fakeResponses.json
MAX_FAKE_RESPONSE_FILESIZE_BYTES=50000
```

---

## 🛡️ Security Disclaimer

This project **does not distribute real malware or compression bombs**. Payloads are corrupted or harmless, intended for research, honeypotting, or DDoS simulation use only.

Learn more about ZIP bombs: [https://blog.haschek.at/2017/how-to-defend-your-website-with-zip-bombs.html](https://blog.haschek.at/2017/how-to-defend-your-website-with-zip-bombs.html)

---

## 🌐 Reverse Proxy Setup (e.g., Nginx, Traefik)

When deploying Boomberman behind a reverse proxy, ensure the following:

### Nginx Example

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik Example (docker-compose snippet)

```yaml
services:
  boomberman:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.boomberman.rule=Host(`yourdomain.com`)"
      - "traefik.http.routers.boomberman.entrypoints=web"
      - "traefik.http.services.boomberman.loadbalancer.server.port=3000"
```

> 🔒 Tip: If you're running behind HTTPS, ensure the `X-Forwarded-Proto` header is correctly set by your proxy for accurate request logging and security analysis.

---

## 📜 License

[MIT — © 2025 Marcel Rösler](./LICENSE)
