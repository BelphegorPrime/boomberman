import fs from 'fs';
import path from 'path';
import { ensureDirExistence } from './ensureDirExistence.js';

const banFile =
  process.env.BAN_FILE_PATH || path.resolve(process.cwd(), 'data/banned.json');
ensureDirExistence(banFile);

const logFile =
  process.env.EVENT_LOG_PATH || path.resolve(process.cwd(), 'logs/events.log');
ensureDirExistence(logFile);

let ipAccessData: Record<string, { count: number; lastAccess: number }> = {};

function loadBanFile() {
  try {
    const data = fs.readFileSync(banFile, 'utf-8');
    ipAccessData = JSON.parse(data);
  } catch {
    ipAccessData = {};
  }
}
loadBanFile();

function saveBanFile() {
  fs.writeFileSync(banFile, JSON.stringify(ipAccessData, null, 2));
}

const CLEANUP_INTERVAL = 60_000;
const MAX_IDLE_TIME = 5 * 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of Object.entries(ipAccessData)) {
    if (now - data.lastAccess > MAX_IDLE_TIME) {
      delete ipAccessData[ip];
    }
  }
  saveBanFile();
}, CLEANUP_INTERVAL);

export function isBanned(ip: string): boolean {
  return ipAccessData[ip] && ipAccessData[ip].count >= 3;
}

export function banIP(ip: string) {
  const now = Date.now();
  const entry = ipAccessData[ip] || { count: 0, lastAccess: 0 };
  const timeSinceLast = now - entry.lastAccess;

  if (timeSinceLast > 30_000) {
    entry.count = 0;
  }

  entry.count += 1;
  entry.lastAccess = now;
  ipAccessData[ip] = entry;

  saveBanFile();
  console.warn(`BANNED IP: ${ip}`);
}

export async function logTarPit({
  ip,
  delay,
  ua,
}: {
  ip: string;
  delay: number;
  ua: string;
}) {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] Tarpitting ${ip} with ${delay}ms delay (UA: ${ua})\n`;
  fs.appendFileSync(logFile, line);
}

export function log(data: string) {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] ${data}\n`;
  fs.appendFileSync(logFile, line);
  console.log(line.trim());
  return { timestamp };
}

export async function logThreat(
  type:
    | 'DIRECTORY_TRAVERSAL_ATTEMPT'
    | 'BOT_TOOLKIT_DETECTED'
    | 'CAPTCHA'
    | 'HONEYPOT_HIT'
    | 'FILE_DOWNLOAD',
  target: string,
  ip: string,
) {
  const { timestamp } = log(`${type} from ${ip} -> ${target}`);

  switch (type) {
    case 'CAPTCHA': {
      break;
    }
    case 'BOT_TOOLKIT_DETECTED':
    case 'HONEYPOT_HIT':
    case 'FILE_DOWNLOAD': {
      banIP(ip);
    }
  }

  await sendWebhookAlert({ type, target, ip, timestamp });
}

export async function sendWebhookAlert(payload: {
  type: string;
  target: string;
  ip: string;
  timestamp: string;
}) {
  const url = process.env.WEBHOOK_URL;
  if (!url) {
    return;
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      console.error(`Webhook failed: ${res.status} ${res.statusText}`);
    } else {
      console.log(`Webhook alert sent for ${payload.ip}`);
    }
  } catch (err: unknown) {
    console.error('Webhook fetch failed:', (err as Error).message);
  }
}
