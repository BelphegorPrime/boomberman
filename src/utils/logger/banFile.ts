import path from 'node:path';
import fs from 'node:fs';
import schedule from 'node-schedule';
import { ensureDirExistence } from '../ensureDirExistence.js';
import { rotateFile, RotateFileOptions } from '../rotateFile.js';
import { isTest } from '../isTest.js';

let banData: Record<string, { count: number; lastAccess: number }> = {};
let allBanData: Record<string, { count: number; lastAccess: number }> = {};

const banFile =
  process.env.BAN_FILE_PATH || path.resolve(process.cwd(), 'data/banned.json');
ensureDirExistence(banFile);
const allBanFile = path.join(path.dirname(banFile), 'all_banned.json');

const rotateFileOptions: RotateFileOptions = {
  dir: path.dirname(allBanFile),
  filename: path.basename(allBanFile),
  retentionDays: parseInt(process.env.LOG_RETENTION_DAYS || '7', 10),
};

if (!isTest) {
  rotateFile(rotateFileOptions);
  schedule.scheduleJob('0 0 * * *', () => rotateFile(rotateFileOptions));

  const CLEANUP_INTERVAL = 60_000;
  const MAX_IDLE_TIME = 5 * 60_000;

  setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of Object.entries(banData)) {
      if (now - data.lastAccess > MAX_IDLE_TIME) {
        delete banData[ip];
      }
    }
    saveBanFile();
  }, CLEANUP_INTERVAL);
}

function loadBanFile() {
  try {
    const data = fs.readFileSync(banFile, 'utf-8');
    banData = JSON.parse(data);
  } catch {
    banData = {};
  }

  try {
    const data = fs.readFileSync(allBanFile, 'utf-8');
    allBanData = JSON.parse(data);
  } catch {
    allBanData = {};
  }
}
loadBanFile();

function saveBanFile(fullSave?: boolean) {
  fs.writeFileSync(banFile, JSON.stringify(banData, null, 2));
  if (fullSave) {
    fs.writeFileSync(allBanFile, JSON.stringify(allBanData, null, 2));
  }
}

function createEntry(baseEntry?: { count: number; lastAccess: number }) {
  const now = Date.now();
  const entry = baseEntry || { count: 0, lastAccess: 0 };
  const timeSinceLast = now - entry.lastAccess;

  if (timeSinceLast > 30_000) {
    entry.count = 0;
  }

  entry.count += 1;
  entry.lastAccess = now;
  return entry;
}

export function isBanned(ip: string): boolean {
  return banData[ip] && banData[ip].count >= 3;
}

export function banIP(ip: string) {
  const entry = createEntry(banData[ip]);
  banData[ip] = entry;
  allBanData[ip] = createEntry(allBanData[ip]);

  saveBanFile(true);
  console.warn(`BANNED IP: ${ip}`);
  return entry;
}

export function clearBanData() {
  if (isTest) {
    banData = {};
    allBanData = {};
  }
}
