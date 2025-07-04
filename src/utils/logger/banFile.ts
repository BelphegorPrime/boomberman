import path from 'node:path';
import fs from 'node:fs';
import { ensureDirExistence } from '../ensureDirExistence.js';

const banFile =
  process.env.BAN_FILE_PATH || path.resolve(process.cwd(), 'data/banned.json');
ensureDirExistence(banFile);
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
  return entry;
}
