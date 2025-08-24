import { banIP } from './banFile.js';
import { getDetectionLogger } from './detectionLogger.js';
import { getMetricsCollector } from './metricsCollector.js';

async function sendWebhookAlert(payload: {
  type: string;
  target: string;
  ip: string;
  timestamp: string;
  data?: Record<string, unknown>;
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

export async function logThreat(
  type:
    | 'HIGH_RISK_BOT_DETECTED'
    | 'SUSPICIOUS_BOT_DETECTED'
    | 'DIRECTORY_TRAVERSAL_ATTEMPT'
    | 'BOT_TOOLKIT_DETECTED'
    | 'CAPTCHA'
    | 'HONEYPOT_HIT'
    | 'FILE_DOWNLOAD',
  target: string,
  ip: string,
  data?: Record<string, unknown>
) {
  console.log(`${type} from ${ip} -> ${target}`, { data });

  // Log structured threat event if correlation ID is available
  if (data?.correlationId) {
    const logger = getDetectionLogger();
    const metricsCollector = getMetricsCollector();

    // Create a mock context for legacy threat logging
    const context = {
      correlationId: data.correlationId as string,
      requestId: data.correlationId as string,
      ip,
      userAgent: data.userAgent as string || 'unknown',
      timestamp: Date.now(),
    };

    // Create a mock request object
    const mockReq = {
      path: target,
      method: 'unknown',
    };

    // Create a mock detection result for legacy threats
    const mockResult = {
      isSuspicious: true,
      suspicionScore: type === 'HIGH_RISK_BOT_DETECTED' ? 90 : 60,
      confidence: 0.8,
      reasons: [{
        category: 'reputation' as const,
        severity: 'high' as const,
        description: `Legacy threat detected: ${type}`,
        score: type === 'HIGH_RISK_BOT_DETECTED' ? 90 : 60,
      }],
      fingerprint: `legacy-${type.toLowerCase()}`,
      metadata: {
        timestamp: Date.now(),
        processingTime: 0,
        detectorVersions: { legacy: '1.0.0' },
      },
    };

    // Determine action based on threat type
    let action: 'BANNED' | 'TARPITTED' | 'RATE_LIMITED' | 'BLOCKED' = 'RATE_LIMITED';
    if (['BOT_TOOLKIT_DETECTED', 'HONEYPOT_HIT', 'FILE_DOWNLOAD'].includes(type)) {
      action = 'BANNED';
    } else if (type === 'HIGH_RISK_BOT_DETECTED') {
      action = 'BLOCKED';
    }

    logger.logThreatAction(context, action, mockResult, mockReq);

    // Record metrics for legacy threats
    const mockMetrics = {
      totalProcessingTime: 0,
      fingerprintingTime: 0,
      behaviorAnalysisTime: 0,
      geoAnalysisTime: 0,
      scoringTime: 0,
      memoryUsage: process.memoryUsage(),
    };

    metricsCollector.recordDetection(ip, mockResult, mockMetrics, action === 'BANNED' || action === 'BLOCKED');
  }

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

  const timestamp = new Date().toISOString();
  await sendWebhookAlert({ type, target, ip, timestamp, data });
}
