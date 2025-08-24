/**
 * Analytics data for detection system performance and threat analysis
 */
export interface DetectionAnalytics {
    /** Total number of requests processed */
    totalRequests: number;
    /** Number of requests flagged as suspicious */
    suspiciousRequests: number;
    /** Number of requests blocked or tarpitted */
    blockedRequests: number;
    /** Number of false positive detections */
    falsePositives: number;
    /** Overall detection accuracy (0-1) */
    detectionAccuracy: number;
    /** Average processing time per request in milliseconds */
    averageProcessingTime: number;
    /** Summary of top threats detected */
    topThreats: ThreatSummary[];
    /** Geographic distribution of requests by country */
    geoDistribution: Record<string, number>;
}

/**
 * Summary information about a detected threat
 */
export interface ThreatSummary {
    /** IP address of the threat */
    ip: string;
    /** Country of origin */
    country: string;
    /** Total number of requests from this IP */
    totalRequests: number;
    /** Average suspicion score */
    averageScore: number;
    /** Timestamp when this threat was last seen */
    lastSeen: number;
    /** Types of threats detected from this IP */
    threatTypes: string[];
}