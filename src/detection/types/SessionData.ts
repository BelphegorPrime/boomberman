/**
 * Session tracking data for behavioral analysis
 */
export interface SessionData {
    /** IP address of the session */
    ip: string;
    /** Timestamp when the session was first seen */
    firstSeen: number;
    /** Timestamp when the session was last seen */
    lastSeen: number;
    /** Total number of requests in this session */
    requestCount: number;
    /** Log of all requests in this session */
    requests: RequestLog[];
    /** Set of unique fingerprints seen in this session */
    fingerprints: Set<string>;
    /** History of suspicion scores for this session */
    suspicionHistory: number[];
}

/**
 * Individual request log entry for session tracking
 */
export interface RequestLog {
    /** Timestamp of the request */
    timestamp: number;
    /** Request path */
    path: string;
    /** HTTP method */
    method: string;
    /** User-Agent header value */
    userAgent: string;
    /** All request headers */
    headers: Record<string, string>;
    /** Response time in milliseconds */
    responseTime: number;
}