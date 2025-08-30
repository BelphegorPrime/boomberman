// Core detection types
export * from './DetectionResult.js';
export * from './HTTPFingerprint.js';
export * from './TLSFingerprint.js';
export * from './BehaviorMetrics.js';
export * from './GeoLocation.js';
export * from './Configuration.js';
export * from './SessionData.js';
export * from './Analytics.js';

// Analyzers
export * from '../analyzers/index.js';

// Import the interfaces for re-export to ensure they're available
import type { DetectionResult, DetectionReason, DetectionMetadata } from './DetectionResult.js';
import type { HTTPFingerprint } from './HTTPFingerprint.js';
import type { TLSFingerprint, BotTLSPattern, TLSFingerprintingConfig } from './TLSFingerprint.js';
import type { BehaviorMetrics } from './BehaviorMetrics.js';
import type { GeoLocation } from './GeoLocation.js';
import type { DetectionConfig, ScoringWeights } from './Configuration.js';
import type { SessionData, RequestLog } from './SessionData.js';
import type { DetectionAnalytics, ThreatSummary } from './Analytics.js';

// Re-export types for convenience
export type {
    DetectionResult,
    DetectionReason,
    DetectionMetadata,
    HTTPFingerprint,
    TLSFingerprint,
    BotTLSPattern,
    TLSFingerprintingConfig,
    BehaviorMetrics,
    GeoLocation,
    DetectionConfig,
    ScoringWeights,
    SessionData,
    RequestLog,
    DetectionAnalytics,
    ThreatSummary,
};