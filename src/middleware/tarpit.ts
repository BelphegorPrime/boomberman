import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { ensureDirExistence, logTarPit } from '../utils/logger';

const tarpitFile = process.env.TARPIT_FILE_PATH || path.resolve(__dirname, '../../data/tarpitAccess.json');
ensureDirExistence(tarpitFile)
const logFile = process.env.EVENT_LOG_PATH || path.resolve(__dirname, '../../logs/events.log');
ensureDirExistence(logFile)

let ipAccessData: Record<string, { count: number, lastAccess: number }> = {};

function loadTarpitData() {
    try {
        const data = fs.readFileSync(tarpitFile, 'utf-8');
        ipAccessData = JSON.parse(data);
    } catch {
        ipAccessData = {};
    }
}
loadTarpitData();

function saveTarpitData() {
    fs.writeFileSync(tarpitFile, JSON.stringify(ipAccessData, null, 2));
}

const suspiciousUserAgents = [/curl/i, /python/i, /nikto/i, /nmap/i];

const CLEANUP_INTERVAL = 60_000;
const MAX_IDLE_TIME = 5 * 60_000;

setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of Object.entries(ipAccessData)) {
        if (now - data.lastAccess > MAX_IDLE_TIME) {
            delete ipAccessData[ip];
        }
    }
    saveTarpitData()
}, CLEANUP_INTERVAL);

export function tarpit(req: Request, res: Response, next: NextFunction) {
    const ip = req.realIp || "unknown";
    const ua = req.headers['user-agent'] || '';
    const now = Date.now();

    const entry = ipAccessData[ip] || { count: 0, lastAccess: 0 };
    const timeSinceLast = now - entry.lastAccess;

    if (timeSinceLast > 30_000) {
        entry.count = 0;
    }

    entry.count += 1;
    entry.lastAccess = now;
    ipAccessData[ip] = entry;
    saveTarpitData()

    const isSuspiciousUA = suspiciousUserAgents.some(pattern => pattern.test(ua));
    const isHighFreq = entry.count > 10;

    if (isSuspiciousUA || isHighFreq) {
        const delay = Math.min(entry.count * 1000, 30_000);
        logTarPit({ ip, delay, ua })

        setTimeout(() => {
            if (entry.count > 20) {
                req.socket.setTimeout(0);
                return;
            } else {
                res.status(429).send('Too many suspicious requests. Slow down.');
            }
        }, delay);

        return;
    }

    next();
}
