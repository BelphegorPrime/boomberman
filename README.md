<p align="center"><img src=".github/assets/fullLogo.png" style="border-radius:8px;" alt="Banner" width="200"></p>

# Boomberman

An advanced honeypot and threat detection platform for cybersecurity research and intrusion detection.

> **Purpose**: Boomberman is a comprehensive security testing platform that combines sophisticated bot detection, realistic honeypots, and AI-powered deception to attract, analyze, and study automated attacks and threat actors.

---

## 🛡️ Core Features

### Advanced Bot Detection
- **Multi-layered Analysis**: HTTP fingerprinting, behavioral analysis, and geographic profiling
- **Real-time Scoring**: 0-100 threat scoring with configurable thresholds
- **TLS Fingerprinting**: Advanced client identification through TLS characteristics
- **Behavioral Tracking**: Request timing, pattern analysis, and session monitoring
- **Whitelist Management**: Comprehensive IP, ASN, and user-agent whitelisting

### Intelligent Honeypots
- **Dynamic Content**: AI-powered fake responses and realistic data generation
- **Adaptive Deception**: Content that adapts based on attacker behavior
- **Fake ZIP/GZIP bombs** _(non-malicious, safe for testing)_
- **Simulated vulnerabilities** and admin panels
- **Captcha traps** to detect automation

### Performance & Monitoring
- **Real-time Analytics**: Comprehensive threat metrics and performance monitoring
- **Correlation Tracking**: Request correlation across detection systems
- **Error Handling**: Robust fallback mechanisms and timeout protection
- **Caching System**: Optimized performance with intelligent caching
- **Webhook Integration**: Real-time alerting and external system integration

### AI Integration
- **Ollama Support**: Local AI models for generating realistic fake responses
- **Automated Content**: Hourly generation of fake logs and responses
- **Adaptive Responses**: Context-aware content generation based on threats

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
   # Edit .env to configure detection thresholds and AI settings
   ```

2. **Choose your deployment**:
   ```bash
   # Option A: Docker (recommended)
   docker compose up --build
   
   # Option B: Node.js development
   npm install && npm run dev
   
   # Option C: Full stack with AI and proxy
   docker compose --profile proxy up --build
   ```

3. **Test the detection system**:
   ```bash
   # Test basic honeypot
   curl http://localhost:3000/tool/pot/admin
   
   # Test file serving
   curl http://localhost:3000/public/malware.zip
   
   # Test bot detection (rapid requests)
   for i in {1..10}; do curl -H "User-Agent: bot" http://localhost:3000/; done
   
   # Check metrics
   curl http://localhost:3000/metrics
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
- **boomberman**: Main honeypot application with enhanced bot detection
- **ollama**: Local AI service for generating fake responses (optional)
- **nginx**: Reverse proxy with rate limiting (optional, use `--profile proxy`)

#### Docker Compose Features
- **Health checks**: Automatic service health monitoring with `/api/health` endpoint
- **Volume persistence**: Data, logs, AI responses, and GeoIP databases persist between restarts
- **Network isolation**: Services communicate on isolated bridge network
- **Resource limits**: Configurable memory and CPU constraints
- **Performance monitoring**: Built-in metrics collection and performance tracking
- **SSL ready**: Nginx configuration supports HTTPS (certificates required)

---

## 🧠 AI Integration

Boomberman leverages local AI models to generate realistic fake content and responses, making honeypots more convincing and harder to detect.

### Configuration
Enable AI features in `.env`:

```env
ENABLE_AI_FAKE_RESPONSES=true
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
AI_PRE_POPULATE_CACHE=true
MAX_FAKE_RESPONSE_FILESIZE_BYTES=50000
```

### Capabilities
- **Dynamic Content Generation**: Creates realistic fake API responses, documentation, and error messages
- **Contextual Responses**: Adapts content based on the type of attack or honeypot triggered  
- **Automated Caching**: Hourly background generation and caching of fake responses
- **Content Rotation**: Prevents detection through varied, realistic responses
- **Fallback System**: Graceful degradation when AI services are unavailable

### Supported AI Providers
- **Ollama**: Local AI inference with models like Llama, Mistral, and CodeLlama
- **Extensible**: Architecture supports additional providers (OpenAI, Anthropic, etc.)

---

## 🔍 Enhanced Bot Detection

Boomberman features a sophisticated multi-layered bot detection system that analyzes requests across multiple dimensions to identify automated threats.

### Detection Layers

#### 1. HTTP Fingerprinting
- **Header Analysis**: Examines 15+ HTTP headers for automation signatures
- **Missing Headers**: Detects absent browser-standard headers
- **Header Patterns**: Identifies automation frameworks (Selenium, Puppeteer, curl, etc.)
- **TLS Fingerprinting**: Advanced client identification through TLS handshake analysis

#### 2. Behavioral Analysis  
- **Timing Patterns**: Detects sub-human request intervals and consistent timing
- **Session Tracking**: Monitors request sequences and navigation patterns
- **Consistency Scoring**: Identifies overly consistent automated behavior
- **Rate Analysis**: Flags rapid-fire requests and burst patterns

#### 3. Geographic Analysis
- **GeoIP Integration**: MaxMind GeoLite2 database for location analysis
- **Risk Scoring**: Country-based risk assessment with configurable high-risk regions
- **Infrastructure Detection**: Identifies VPN, proxy, hosting, and Tor traffic
- **ASN Analysis**: Autonomous System Number reputation and categorization

#### 4. Threat Scoring Engine
- **Weighted Scoring**: Configurable weights across all detection dimensions
- **Confidence Levels**: Provides confidence metrics for each detection
- **Threshold Management**: Separate thresholds for suspicious and high-risk classifications
- **Correlation**: Links related requests for comprehensive threat assessment

### Whitelist Management
- **Multi-dimensional**: IP addresses, ASN numbers, and user-agent patterns
- **Dynamic Updates**: Runtime whitelist modifications with audit logging
- **Monitoring Tools**: Built-in bypass for legitimate security scanners
- **Expiration Support**: Time-based whitelist entries with automatic cleanup

### Performance Features
- **Timeout Protection**: 50ms processing timeout with fallback mechanisms
- **Caching**: Intelligent caching of analysis results and GeoIP data
- **Error Handling**: Robust error recovery with detailed logging
- **Metrics Collection**: Comprehensive performance and accuracy metrics

---

## 🌐 API Endpoints

| Endpoint        | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| `/api/health`   | Health check endpoint for monitoring and load balancers     |
| `/public/*`     | Serves fake files, ZIP bombs, and simulated payloads        |
| `/tool/pot/*`   | Honeypot endpoints that trigger threat analysis and logging |
| `/tool/captcha` | CAPTCHA challenge endpoint to trap automated scripts        |
| `/tool/tarpit`  | Tarpit test endpoint with configurable delays               |
| `/metrics`      | Threat metrics and system performance data                  |
| `/gen`          | AI response generation endpoint (when AI is enabled)        |

### Dynamic Tool Activation
Use query parameters to enable specific tools:
- `?tools=tarpit` - Apply request delays
- `?tools=honeypot` - Trigger honeypot analysis  
- `?tools=captcha` - Force CAPTCHA challenge

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

## 📊 Project Status

Boomberman is actively developed with a focus on advanced threat detection and realistic deception techniques.

### ✅ Implemented Features
- **Enhanced Bot Detection**: Multi-layered analysis with HTTP fingerprinting, behavioral tracking, and geographic profiling
- **Threat Scoring Engine**: Configurable weighted scoring system with confidence metrics
- **Whitelist Management**: Comprehensive IP, ASN, and user-agent whitelisting with dynamic updates
- **Performance Monitoring**: Real-time metrics collection and correlation tracking
- **AI Integration**: Ollama-powered fake response generation with caching
- **Error Handling**: Robust fallback mechanisms and timeout protection
- **Docker Support**: Production-ready containerization with health checks

### 🚧 In Development
- **Real-time Dashboard**: WebSocket-based attack visualization and analytics
- **Advanced Honeypots**: Realistic admin panels (WordPress, phpMyAdmin, cPanel)
- **Threat Intelligence**: Integration with AbuseIPDB, VirusTotal, and custom feeds
- **Machine Learning**: Anomaly detection and attack pattern classification

### 🎯 Roadmap
See [ROADMAP.md](./ROADMAP.md) for detailed development plans and [IMPROVEMENT_TASKS.md](./IMPROVEMENT_TASKS.md) for specific implementation tasks.

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and check the [IMPROVEMENT_TASKS.md](./IMPROVEMENT_TASKS.md) for areas where help is needed.

### Development Setup
```bash
git clone <repository-url>
cd boomberman
npm install
cp .env.example .env
npm run dev
```

### Testing
```bash
npm test                    # Run all tests
npm run test:watch         # Watch mode for development
npm run lint               # Code linting
npm run format             # Code formatting
```

---

## 📜 License

[MIT — © 2025 Marcel Rösler](./LICENSE)
