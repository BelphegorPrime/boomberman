# Boomberman

A harmless honeypot + simulated payload server for security testing.

**Features**:
- Simulated ZIP/GZIP bombs (non-malicious)
- Honeypot endpoints
- Access logging
- Metrics endpoint

**Usage**:
```bash
npm install
npm run dev
```

Docker:

```bash
docker build -t boomberman .
docker run -p 3000:3000 boomberman
```

Security Notice: This project does not contain or distribute real compression bombs.

You can find out more about ZIP Bombs [here](https://blog.haschek.at/2017/how-to-defend-your-website-with-zip-bombs.html)