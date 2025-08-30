<p align="center"><img src=".github/assets/fullLogo.png" style="border-radius:8px;" alt="Banner" width="200"></p>

A honeypot and simulated payload server for safe security testing and intrusion detection.

> **Purpose**: Boomberman simulates malicious activity to attract, detect, and study automated attacks. It includes honeypot endpoints, fake payloads, rate limiting, and AI-powered fake response generation.

---

## 🧪 Features

- **Fake ZIP/GZIP bombs** _(non-malicious, safe for testing)_
- **Tarpit** middleware to delay suspicious requests
- **Honeypot endpoints** that simulate vulnerable tools or pages
- **Captcha endpoint** to trap automated scripts
- **AI-generated fake responses** powered by [Ollama](https://ollama.com/)
- **Hourly background generation** of fake logs/responses
- **Access, event, and threat logging**
- **Webhook support** for real-time alerting
- **Metrics endpoint** for monitoring hits

---

## 🔧 Environment Variables

Configure Boomberman using these environment variables. Copy `.env.example` to `.env` and adjust as needed.

| Variable                                        | Type    | Default                                                                      | Description                                            |
| ----------------------------------------------- | ------- | ---------------------------------------------------------------------------- | ------------------------------------------------------ |
| **Server Configuration**                        |
| `PORT`                                          | number  | `3000`                                                                       | Server port                                            |
| `NODE_ENV`                                      | string  | -                                                                            | Environment mode (`development`, `production`, `test`) |
| `WEBHOOK_URL`                                   | string  | -                                                                            | Webhook endpoint for real-time alerts                  |
| **File Paths & Storage**                        |
| `DATA_DIR`                                      | string  | `./data`                                                                     | Base directory for data files                          |
| `BAN_FILE_PATH`                                 | string  | `/data/banned.json`                                                          | Path to banned IPs file                                |
| `LOG_FILE_PATH`                                 | string  | `/data/app.log`                                                              | Main application log file                              |
| `AI_FAKE_RESPONSES_PATH`                        | string  | `/data/fakeResponses.jsonl`                                                  | AI-generated fake responses cache                      |
| `LOG_RETENTION_DAYS`                            | number  | `7`                                                                          | Log file retention period                              |
| **AI Integration**                              |
| `ENABLE_AI_FAKE_RESPONSES`                      | boolean | `false`                                                                      | Enable AI-powered fake response generation             |
| `AI_PROVIDER`                                   | string  | `ollama`                                                                     | AI provider (`ollama` currently supported)             |
| `OLLAMA_URL`                                    | string  | `http://localhost:11434`                                                     | Ollama server URL                                      |
| `OLLAMA_MODEL`                                  | string  | `llama3.2`                                                                   | Ollama model to use                                    |
| `AI_PRE_POPULATE_CACHE`                         | boolean | `true`                                                                       | Pre-populate AI response cache on startup              |
| `MAX_FAKE_RESPONSE_FILESIZE_BYTES`              | number  | `50000`                                                                      | Maximum size for fake response cache file              |
| **GeoIP Configuration**                         |
| `GEOLITE2_CITY_DB_PATH`                         | string  | `./src/data/geoip/GeoLite2-City.mmdb`                                        | Path to GeoLite2 City database                         |
| `GEOLITE2_ASN_DB_PATH`                          | string  | `./src/data/geoip/GeoLite2-ASN.mmdb`                                         | Path to GeoLite2 ASN database                          |
| **Enhanced Bot Detection**                      |
| `BOT_DETECTION_ENABLED`                         | boolean | `true`                                                                       | Enable enhanced bot detection system                   |
| **Detection Scoring Weights** (must sum to 1.0) |
| `BOT_DETECTION_WEIGHT_FINGERPRINT`              | float   | `0.3`                                                                        | Weight for fingerprint analysis                        |
| `BOT_DETECTION_WEIGHT_BEHAVIORAL`               | float   | `0.3`                                                                        | Weight for behavioral analysis                         |
| `BOT_DETECTION_WEIGHT_GEOGRAPHIC`               | float   | `0.2`                                                                        | Weight for geographic analysis                         |
| `BOT_DETECTION_WEIGHT_REPUTATION`               | float   | `0.2`                                                                        | Weight for reputation analysis                         |
| **Detection Thresholds** (0-100 scale)          |
| `BOT_DETECTION_THRESHOLD_SUSPICIOUS`            | number  | `30`                                                                         | Threshold for marking requests as suspicious           |
| `BOT_DETECTION_THRESHOLD_HIGH_RISK`             | number  | `70`                                                                         | Threshold for high-risk classification                 |
| **Behavioral Analysis**                         |
| `BOT_DETECTION_MIN_HUMAN_INTERVAL`              | number  | `500`                                                                        | Minimum interval (ms) between human requests           |
| `BOT_DETECTION_MAX_CONSISTENCY`                 | float   | `0.8`                                                                        | Maximum consistency score for human behavior           |
| `BOT_DETECTION_SESSION_TIMEOUT`                 | number  | `1800000`                                                                    | Session timeout in milliseconds (30 min)               |
| **Geographic Analysis**                         |
| `BOT_DETECTION_HIGH_RISK_COUNTRIES`             | string  | `CN,RU,KP,IR`                                                                | Comma-separated high-risk country codes                |
| `BOT_DETECTION_VPN_PENALTY`                     | number  | `20`                                                                         | Penalty score for VPN usage                            |
| `BOT_DETECTION_HOSTING_PENALTY`                 | number  | `15`                                                                         | Penalty score for hosting provider IPs                 |
| **Whitelist Configuration**                     |
| `BOT_DETECTION_WHITELIST_IPS`                   | string  | `127.0.0.1,::1`                                                              | Comma-separated whitelisted IP addresses               |
| `BOT_DETECTION_WHITELIST_ASNS`                  | string  | -                                                                            | Comma-separated whitelisted ASN numbers                |
| `BOT_DETECTION_REQUIRED_HEADERS`                | string  | `Accept,Accept-Language,Accept-Encoding,Connection,Cache-Control,User-Agent` | Required HTTP headers for legitimate requests          |

---

## 🚀 Quick Start

1. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd boomberman
   cp .env.example .env
   ```

2. **Choose your setup**:
   ```bash
   # Option A: Docker (recommended)
   docker compose up --build
   
   # Option B: Node.js development
   npm install && npm run dev
   
   # Option C: Full stack with AI and proxy
   docker compose --profile proxy up --build
   ```

3. **Test the honeypot**:
   ```bash
   curl http://localhost:3000/honeypots/admin
   curl http://localhost:3000/files/malware.zip
   ```

---

## ⚙️ Installation

### 1. Native (Node.js)

```bash
npm install
npm run dev
```

### 2. Docker

```bash
docker build -t boomberman .
docker run -p 3000:3000 boomberman
```

### 3. Docker Compose

#### Basic Setup
```bash
docker compose up --build
```

#### Full Setup with Ollama AI and Nginx Proxy
```bash
# Start with Ollama for AI-powered responses
docker compose --profile proxy up --build

# Or start individual services
docker compose up boomberman ollama --build
```

#### Service Overview
- **boomberman**: Main honeypot application
- **ollama**: Local AI service for generating fake responses (optional)
- **nginx**: Reverse proxy with rate limiting (optional, use `--profile proxy`)

#### Docker Compose Features
- **Health checks**: Automatic service health monitoring
- **Volume persistence**: Data, logs, and AI responses persist between restarts
- **Network isolation**: Services communicate on isolated bridge network
- **Resource limits**: Configurable logging and resource constraints
- **SSL ready**: Nginx configuration supports HTTPS (certificates required)

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

- Periodically generate and cache fake responses using the AI
- Serve corrupted or misleading payloads to attackers via honeypots

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
BAN_FILE_PATH=/data/banned.json
LOG_FILE_PATH=/data/app.log
AI_FAKE_RESPONSES_PATH=/data/fakeResponses.jsonl
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
      - 'traefik.enable=true'
      - 'traefik.http.routers.boomberman.rule=Host(`yourdomain.com`)'
      - 'traefik.http.routers.boomberman.entrypoints=web'
      - 'traefik.http.services.boomberman.loadbalancer.server.port=3000'
```

> 🔒 Tip: If you're running behind HTTPS, ensure the `X-Forwarded-Proto` header is correctly set by your proxy for accurate request logging and security analysis.

---

## 📜 License

[MIT — © 2025 Marcel Rösler](./LICENSE)
