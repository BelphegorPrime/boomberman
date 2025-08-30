import path from 'node:path';
import fs from 'node:fs';
import schedule from 'node-schedule';
import { ensureDirExistence } from '../ensureDirExistence.js';
import { rotateFile, RotateFileOptions } from '../rotateFile.js';
import { isTest } from '../isTest.js';

interface BanEntry {
  count: number;
  lastAccess: number;
  suspicionScore?: number;
  confidence?: number;
  enhancedDetections?: number;
}

let banData: Record<string, BanEntry> = {};
let allBanData: Record<string, BanEntry> = {};

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

function createEntry(baseEntry?: BanEntry, suspicionScore?: number, confidence?: number): BanEntry {
  const now = Date.now();
  const entry: BanEntry = baseEntry || {
    count: 0,
    lastAccess: 0,
    enhancedDetections: 0
  };
  const timeSinceLast = now - entry.lastAccess;

  if (timeSinceLast > 30_000) {
    entry.count = 0;
    entry.enhancedDetections = 0;
  }

  entry.count += 1;
  entry.lastAccess = now;

  // Update enhanced detection data if provided
  if (suspicionScore !== undefined && confidence !== undefined) {
    entry.suspicionScore = Math.max(entry.suspicionScore || 0, suspicionScore);
    entry.confidence = Math.max(entry.confidence || 0, confidence);
    entry.enhancedDetections = (entry.enhancedDetections || 0) + 1;
  }

  return entry;
}

export function isBanned(ip: string): boolean {
  const entry = banData[ip];
  if (!entry) return false;

  // Enhanced banning logic considering confidence levels
  if (entry.enhancedDetections && entry.enhancedDetections > 0) {
    const suspicionScore = entry.suspicionScore || 0;
    const confidence = entry.confidence || 0;

    // High confidence, medium-high score - ban after fewer attempts
    if (confidence >= 0.8 && suspicionScore >= 40) {
      return entry.count >= 2;
    }

    // Medium confidence or score - standard threshold
    if (confidence >= 0.5 || suspicionScore >= 30) {
      return entry.count >= 3;
    }

    // Low confidence - require more attempts
    if (confidence < 0.5 && suspicionScore < 30) {
      return entry.count >= 5;
    }
  }

  // Legacy banning logic - 3 strikes
  return entry.count >= 3;
}

export function banIP(ip: string): BanEntry {
  const entry = createEntry(banData[ip]);
  banData[ip] = entry;
  allBanData[ip] = createEntry(allBanData[ip]);

  saveBanFile(true);
  console.warn(`BANNED IP: ${ip} (Legacy detection)`);
  return entry;
}

export function banIPWithConfidence(ip: string, suspicionScore: number, confidence: number): BanEntry {
  const entry = createEntry(banData[ip], suspicionScore, confidence);
  banData[ip] = entry;
  allBanData[ip] = createEntry(allBanData[ip], suspicionScore, confidence);

  saveBanFile(true);

  const logData = {
    score: suspicionScore,
    confidence: confidence,
    count: entry.count,
    enhancedDetections: entry.enhancedDetections,
    willBeBanned: isBanned(ip)
  };

  console.warn(`BANNED IP: ${ip} (Enhanced detection)`, logData);
  return entry;
}

export function clearBanData() {
  if (isTest) {
    banData = {};
    allBanData = {};
  }
}

export function getBanEntry(ip: string): BanEntry | undefined {
  return banData[ip];
}

export function getBanStatistics(): {
  totalBannedIPs: number;
  enhancedDetections: number;
  legacyDetections: number;
  averageSuspicionScore: number;
  averageConfidence: number;
} {
  const entries = Object.values(banData);
  const enhancedEntries = entries.filter(e => e.enhancedDetections && e.enhancedDetections > 0);
  const legacyEntries = entries.filter(e => !e.enhancedDetections || e.enhancedDetections === 0);

  const totalSuspicionScore = enhancedEntries.reduce((sum, e) => sum + (e.suspicionScore || 0), 0);
  const totalConfidence = enhancedEntries.reduce((sum, e) => sum + (e.confidence || 0), 0);

  return {
    totalBannedIPs: entries.length,
    enhancedDetections: enhancedEntries.length,
    legacyDetections: legacyEntries.length,
    averageSuspicionScore: enhancedEntries.length > 0 ? totalSuspicionScore / enhancedEntries.length : 0,
    averageConfidence: enhancedEntries.length > 0 ? totalConfidence / enhancedEntries.length : 0,
  };
}
