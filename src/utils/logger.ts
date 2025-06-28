import fs from 'fs';
import path from 'path';

const banFile = process.env.BAN_FILE_PATH || path.resolve(__dirname, '../../data/banned.json');
const logFile = process.env.EVENT_LOG_PATH || path.resolve(__dirname, '../../logs/events.log');

export function ensureDirExistence(filePath: string) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}
ensureDirExistence(banFile);
ensureDirExistence(logFile);

function loadBanList(): Set<string> {
    try {
        const data = fs.readFileSync(banFile, 'utf-8');
        const parsed = JSON.parse(data);
        return new Set(Array.isArray(parsed) ? parsed : []);
    } catch {
        return new Set();
    }
}

const bannedIPs = loadBanList();

function saveBanList(banned: Set<string>) {
    fs.writeFileSync(banFile, JSON.stringify([...banned], null, 2));
}

export function isBanned(ip: string): boolean {
    return bannedIPs.has(ip);
}

export function banIP(ip: string) {
    if (!bannedIPs.has(ip)) {
        bannedIPs.add(ip);
        saveBanList(bannedIPs);
        console.warn(`BANNED IP: ${ip}`);
    }
}

export async function logTarPit({ ip, delay, ua }: { ip: string, delay: number, ua: string }) {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] Tarpitting ${ip} with ${delay}ms delay (UA: ${ua})\n`;
    fs.appendFileSync(logFile, line);
}

export async function logThreat(type: 'BOT_TOOLKIT_DETECTED' | 'CAPTCHA' | 'HONEYPOT_HIT' | 'FILE_DOWNLOAD', target: string, ip: string) {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] ${type} from ${ip} -> ${target}\n`;
    fs.appendFileSync(logFile, line);
    console.log(line.trim());

    switch (type) {
        case 'CAPTCHA': {
            break
        }
        case 'BOT_TOOLKIT_DETECTED':
        case 'HONEYPOT_HIT':
        case 'FILE_DOWNLOAD': {
            banIP(ip);
            await sendWebhookAlert({ type, target, ip, timestamp });
        }
    }
}

export async function sendWebhookAlert(payload: { type: string, target: string, ip: string, timestamp: string }) {
    const url = process.env.WEBHOOK_URL;
    console.log({ url })
    if (!url) return;

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
    } catch (err: any) {
        console.error('Webhook fetch failed:', err.message);
    }
}

