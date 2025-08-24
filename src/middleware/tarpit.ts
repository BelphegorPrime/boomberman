import type { Request, Response, NextFunction } from 'express';
import { isKnownBot } from '../utils/isKnownBot.js';
import { banIP } from '../utils/logger/banFile.js';

export function tarpit(req: Request, res: Response, next: NextFunction) {
  const ip = req.realIp || 'unknown';
  const ua = req.headers['user-agent'] || '';

  const entry = banIP(ip);

  // Check enhanced detection results first
  const isEnhancedSuspicious = req.suspiciousRequest || false;
  const suspicionScore = req.suspicionScore || 0;

  // Fallback to legacy detection
  const isSuspiciousUA = isKnownBot(ua);
  const isHighFreq = entry.count > 10;

  // Determine if request should be tarpitted
  const shouldTarpit = isEnhancedSuspicious || isSuspiciousUA || isHighFreq;

  if (shouldTarpit) {
    // Calculate delay based on enhanced detection score or legacy logic
    let delay: number;

    if (isEnhancedSuspicious && suspicionScore > 0) {
      // Use enhanced detection score for more precise delays
      // Score 30-50: 1-5 seconds, Score 50-70: 5-15 seconds
      const scoreBasedDelay = Math.min((suspicionScore - 30) * 375, 15_000); // Max 15s for score-based
      delay = Math.max(scoreBasedDelay, 1000); // Minimum 1s delay
    } else {
      // Legacy delay calculation
      delay = Math.min(entry.count * 1000, 30_000);
    }

    console.log(`Tarpitting ${ip} with ${delay}ms delay (Enhanced: ${isEnhancedSuspicious}, Score: ${suspicionScore}, UA: ${ua})`);

    req.socket.setTimeout(0);

    setTimeout(() => {
      res.status(429).send('Too many suspicious requests. Slow down.');
    }, delay);

    return;
  }

  next();
}
