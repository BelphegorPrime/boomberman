import type { GeoLocation } from './GeoLocation.js';
import type { BehaviorMetrics } from './BehaviorMetrics.js';

/**
 * Core detection result interface representing the outcome of bot detection analysis
 */
export interface DetectionResult {
    /** Whether the request is considered suspicious */
    isSuspicious: boolean;
    /** Suspicion score from 0-100 */
    suspicionScore: number;
    /** Confidence level in the detection from 0-1 */
    confidence: number;
    /** List of reasons contributing to the suspicion score */
    reasons: DetectionReason[];
    /** Unique fingerprint identifying the request characteristics */
    fingerprint: string;
    /** Additional metadata about the detection process */
    metadata: DetectionMetadata;
}

/**
 * Individual reason contributing to the overall suspicion score
 */
export interface DetectionReason {
    /** Category of detection that triggered this reason */
    category: 'fingerprint' | 'behavioral' | 'geographic' | 'reputation';
    /** Severity level of this detection reason */
    severity: 'low' | 'medium' | 'high';
    /** Human-readable description of the detection reason */
    description: string;
    /** Numeric score contribution (0-100) */
    score: number;
}

/**
 * Metadata about the detection process and results
 */
export interface DetectionMetadata {
    /** Timestamp when detection was performed */
    timestamp: number;
    /** Time taken to process the detection in milliseconds */
    processingTime: number;
    /** Version information for each detector component */
    detectorVersions: Record<string, string>;
    /** Geographic data if available */
    geoData?: GeoLocation;
    /** Behavioral analysis data if available */
    behaviorData?: BehaviorMetrics;
}