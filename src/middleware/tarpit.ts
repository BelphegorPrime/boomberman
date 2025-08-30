import type { Request, Response, NextFunction } from 'express';
import { isKnownBot } from '../utils/isKnownBot.js';
import { banIP, banIPWithConfidence } from '../utils/logger/banFile.js';
import type { DetectionResult } from '../detection/types/index.js';

export function tarpit(req: Request, res: Response, next: NextFunction) {
  const ip = req.realIp || 'unknown';
  const ua = req.headers['user-agent'] || '';

  // Get enhanced detection results if available
  const detectionResult: DetectionResult | undefined = req.detectionResult;
  const isEnhancedSuspicious = req.suspiciousRequest || false;
  const suspicionScore = req.suspicionScore || detectionResult?.suspicionScore || 0;
  const confidence = detectionResult?.confidence || 0;

  // Use enhanced ban system if detection result is available
  let entry;
  if (detectionResult && detectionResult.isSuspicious) {
    // Use confidence-aware banning for enhanced detection
    entry = banIPWithConfidence(ip, suspicionScore, confidence);
  } else {
    // Fallback to legacy ban system
    entry = banIP(ip);
  }

  // Fallback to legacy detection if enhanced detection not available
  const isSuspiciousUA = isKnownBot(ua);
  const isHighFreq = entry.count > 10;

  // Determine if request should be tarpitted
  const shouldTarpit = isEnhancedSuspicious || isSuspiciousUA || isHighFreq;

  if (shouldTarpit) {
    // Calculate delay based on enhanced detection score or legacy logic
    let delay: number;

    if (isEnhancedSuspicious && suspicionScore > 0) {
      // Use enhanced detection score for more precise delays
      // Score 30-50: 1-5 seconds, Score 50-70: 5-15 seconds, Score 70+: 15-30 seconds
      if (suspicionScore >= 70) {
        // High risk - longer delays with confidence multiplier
        const baseDelay = Math.min((suspicionScore - 70) * 500, 15_000); // 0-15s base
        const confidenceMultiplier = Math.max(confidence, 0.5); // Minimum 0.5x multiplier
        delay = Math.max(baseDelay * confidenceMultiplier + 15_000, 15_000); // 15-30s total
      } else if (suspicionScore >= 50) {
        // Medium-high risk - moderate delays
        delay = Math.min((suspicionScore - 50) * 500 + 5_000, 15_000); // 5-15s
      } else {
        // Low-medium risk - short delays
        delay = Math.min((suspicionScore - 30) * 250 + 1_000, 5_000); // 1-5s
      }
    } else {
      // Legacy delay calculation
      delay = Math.min(entry.count * 1000, 30_000);
    }

    // Log tarpit action with enhanced information
    const logData = {
      enhanced: isEnhancedSuspicious,
      score: suspicionScore,
      confidence: confidence,
      legacy: isSuspiciousUA,
      highFreq: isHighFreq,
      correlationId: req.correlationId,
    };

    console.log(`Tarpitting ${ip} with ${delay}ms delay`, logData);

    req.socket.setTimeout(0);

    setTimeout(() => {
      res.status(429).send('Too many suspicious requests. Slow down.');
    }, delay);

    return;
  }

  next();
}
