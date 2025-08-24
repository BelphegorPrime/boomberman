import 'express';
import type { DetectionResult } from '../src/detection/types/index.js';

interface PerformanceMetrics {
  totalTime: number;
  fingerprintTime: number;
  behaviorTime: number;
  geoTime: number;
  scoringTime: number;
  timeoutOccurred: boolean;
}

declare module 'express-serve-static-core' {
  interface Request {
    realIp?: string;
    detectionResult?: DetectionResult;
    detectionMetrics?: PerformanceMetrics;
    detectionError?: string;
    suspiciousRequest?: boolean;
    suspicionScore?: number;
    correlationId?: string;
    id?: string;
    sessionID?: string;
  }
}
