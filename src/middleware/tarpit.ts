import type { Request, Response, NextFunction } from 'express';
import { isKnownBot } from '../utils/isKnownBot.js';
import { banIP } from '../utils/logger/banFile.js';

export function tarpit(req: Request, res: Response, next: NextFunction) {
  const ip = req.realIp || 'unknown';
  const ua = req.headers['user-agent'] || '';

  const entry = banIP(ip);

  const isSuspiciousUA = isKnownBot(ua);
  const isHighFreq = entry.count > 10;

  if (isSuspiciousUA || isHighFreq) {
    const delay = Math.min(entry.count * 1000, 30_000);
    console.log(`Tarpitting ${ip} with ${delay}ms delay(UA: ${ua})`);

    req.socket.setTimeout(0);

    setTimeout(() => {
      res.status(429).send('Too many suspicious requests. Slow down.');
    }, delay);

    return;
  }

  next();
}
