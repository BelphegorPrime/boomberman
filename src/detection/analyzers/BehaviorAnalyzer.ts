import { Request } from 'express';
import { BehaviorMetrics, SessionData, RequestLog } from '../types/index.js';
import { detectionErrorHandler, DetectionErrorType } from '../ErrorHandler.js';

/**
 * Configuration interface for behavioral analysis
 */
interface BehavioralConfig {
    /** Minimum interval between requests for human-like behavior (ms) */
    minHumanInterval: number;
    /** Maximum timing consistency score before flagging as robotic (0-1) */
    maxConsistency: number;
    /** Session timeout in milliseconds */
    sessionTimeout: number;
}

/**
 * Analyzes behavioral patterns in HTTP requests to detect automated behavior
 */
export class BehaviorAnalyzer {
    private ipSessions: Map<string, SessionData> = new Map();
    private readonly sessionTimeout: number;
    private readonly minHumanInterval: number;
    private readonly maxConsistency: number;

    /**
     * Constructor for BehaviorAnalyzer
     */
    constructor(config?: BehavioralConfig) {
        this.sessionTimeout = config?.sessionTimeout || 30 * 60 * 1000; // 30 minutes
        this.minHumanInterval = config?.minHumanInterval || 500; // 500ms minimum human interval
        this.maxConsistency = config?.maxConsistency || 0.8; // Maximum timing consistency for humans
    }

    /**
     * Analyzes behavioral patterns for a given IP and request
     */
    analyze(ip: string, req: Request): BehaviorMetrics {
        try {
            this.trackSession(ip, req);
            const session = this.ipSessions.get(ip);

            if (!session) {
                // Return neutral metrics if session tracking failed
                return this.createNeutralBehaviorMetrics();
            }

            return {
                requestInterval: this.calculateAverageInterval(session.requests),
                navigationPattern: this.extractNavigationPattern(session.requests),
                timingConsistency: this.calculateTimingConsistency(session.requests),
                humanLikeScore: this.calculateHumanLikeScore(session),
                sessionDuration: session.lastSeen - session.firstSeen
            };
        } catch (error) {
            const behaviorError = error instanceof Error ? error : new Error('Behavior analysis failed');
            return detectionErrorHandler.handleBehaviorAnalysisError(ip, behaviorError);
        }
    }

    /**
     * Tracks session data for the given IP and request
     */
    private trackSession(ip: string, req: Request): void {
        const now = Date.now();

        // Clean up expired sessions
        this.cleanupExpiredSessions(now);

        let session = this.ipSessions.get(ip);

        if (!session) {
            session = {
                ip,
                firstSeen: now,
                lastSeen: now,
                requestCount: 0,
                requests: [],
                fingerprints: new Set(),
                suspicionHistory: []
            };
            this.ipSessions.set(ip, session);
        }

        // Update session data
        session.lastSeen = now;
        session.requestCount++;

        // Add request log
        const requestLog: RequestLog = {
            timestamp: now,
            path: req.path,
            method: req.method,
            userAgent: req.get('User-Agent') || '',
            headers: { ...req.headers } as Record<string, string>,
            responseTime: 0 // Will be updated by middleware if needed
        };

        session.requests.push(requestLog);

        // Keep only last 100 requests to prevent memory bloat
        if (session.requests.length > 100) {
            session.requests = session.requests.slice(-100);
        }
    }

    /**
     * Calculates average interval between requests
     */
    private calculateAverageInterval(requests: RequestLog[]): number {
        if (requests.length < 2) {
            return 0;
        }

        const intervals: number[] = [];
        for (let i = 1; i < requests.length; i++) {
            intervals.push(requests[i].timestamp - requests[i - 1].timestamp);
        }

        return intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
    }

    /**
     * Extracts navigation pattern from request sequence
     */
    private extractNavigationPattern(requests: RequestLog[]): string[] {
        // Get last 10 requests to analyze recent navigation pattern
        const recentRequests = requests.slice(-10);
        return recentRequests.map(req => `${req.method}:${req.path}`);
    }

    /**
     * Calculates timing consistency score (higher = more robotic)
     */
    private calculateTimingConsistency(requests: RequestLog[]): number {
        if (requests.length < 3) {
            return 0;
        }

        const intervals: number[] = [];
        for (let i = 1; i < requests.length; i++) {
            intervals.push(requests[i].timestamp - requests[i - 1].timestamp);
        }

        if (intervals.length === 0) {
            return 0;
        }

        // Calculate coefficient of variation (std dev / mean)
        const mean = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - mean, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);

        if (mean === 0) {
            return 1; // Perfect consistency (suspicious)
        }

        const coefficientOfVariation = stdDev / mean;

        // Convert to consistency score (lower variation = higher consistency)
        // For perfectly consistent timing (CV = 0), return 1.0
        // For highly variable timing (CV > 1), return close to 0
        // Use inverse relationship: consistency = 1 / (1 + CV)
        return 1 / (1 + coefficientOfVariation);
    }

    /**
     * Calculates overall human-like score based on multiple factors
     */
    private calculateHumanLikeScore(session: SessionData): number {
        let score = 1.0; // Start with perfect human score

        // Factor 1: Request timing analysis
        const avgInterval = this.calculateAverageInterval(session.requests);
        if (avgInterval > 0 && avgInterval < this.minHumanInterval) {
            // Sub-human speed detected
            const speedPenalty = Math.max(0, (this.minHumanInterval - avgInterval) / this.minHumanInterval);
            score -= speedPenalty * 0.4; // Up to 40% penalty for speed
        }

        // Factor 2: Timing consistency
        const consistency = this.calculateTimingConsistency(session.requests);
        if (consistency > 0.6) { // Lower threshold for consistency penalty
            // Too consistent timing (robotic)
            const consistencyPenalty = (consistency - 0.6) / (1 - 0.6);
            score -= consistencyPenalty * 0.4; // Up to 40% penalty for consistency
        }

        // Factor 3: Navigation pattern analysis
        const navigationScore = this.analyzeNavigationHumanness(session.requests);
        score -= (1 - navigationScore) * 0.2; // Up to 20% penalty for robotic navigation

        // Factor 4: Request diversity
        const diversityScore = this.calculateRequestDiversity(session.requests);
        score -= (1 - diversityScore) * 0.1; // Up to 10% penalty for lack of diversity

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Analyzes navigation patterns for human-like behavior
     */
    private analyzeNavigationHumanness(requests: RequestLog[]): number {
        if (requests.length < 2) {
            return 1.0; // Neutral score for insufficient data
        }

        let humanScore = 1.0;

        // Check for rapid-fire identical requests (bot behavior)
        let identicalSequence = 0;
        let maxIdenticalSequence = 0;

        for (let i = 1; i < requests.length; i++) {
            if (requests[i].path === requests[i - 1].path &&
                requests[i].method === requests[i - 1].method) {
                identicalSequence++;
                maxIdenticalSequence = Math.max(maxIdenticalSequence, identicalSequence);
            } else {
                identicalSequence = 0;
            }
        }

        // Penalize long sequences of identical requests
        if (maxIdenticalSequence > 3) {
            humanScore -= Math.min(0.5, maxIdenticalSequence * 0.1);
        }

        // Check for automated flow patterns (e.g., systematic endpoint scanning)
        const uniquePaths = new Set(requests.map(r => r.path));
        const pathVariety = uniquePaths.size / requests.length;

        // Very low path variety might indicate scanning behavior
        if (pathVariety < 0.1 && requests.length > 10) {
            humanScore -= 0.3;
        }

        return Math.max(0, humanScore);
    }

    /**
     * Calculates request diversity score
     */
    private calculateRequestDiversity(requests: RequestLog[]): number {
        if (requests.length === 0) {
            return 1.0;
        }

        const uniqueMethods = new Set(requests.map(r => r.method));
        const uniquePaths = new Set(requests.map(r => r.path));
        const uniqueUserAgents = new Set(requests.map(r => r.userAgent));

        // Calculate diversity based on unique values
        const methodDiversity = uniqueMethods.size / Math.min(requests.length, 5); // Max 5 common methods
        const pathDiversity = uniquePaths.size / requests.length;
        const userAgentDiversity = uniqueUserAgents.size / Math.min(requests.length, 3); // Max 3 different UAs is reasonable

        // Weighted average of diversity factors
        return (methodDiversity * 0.2 + pathDiversity * 0.6 + userAgentDiversity * 0.2);
    }

    /**
     * Cleans up expired sessions to prevent memory leaks
     */
    private cleanupExpiredSessions(currentTime: number): void {
        for (const [ip, session] of this.ipSessions.entries()) {
            if (currentTime - session.lastSeen > this.sessionTimeout) {
                this.ipSessions.delete(ip);
            }
        }
    }

    /**
     * Gets current session data for an IP (for testing/debugging)
     */
    getSession(ip: string): SessionData | undefined {
        return this.ipSessions.get(ip);
    }

    /**
     * Gets total number of active sessions (for monitoring)
     */
    getActiveSessionCount(): number {
        return this.ipSessions.size;
    }

    /**
     * Clears all session data (for testing)
     */
    clearSessions(): void {
        this.ipSessions.clear();
    }

    /**
     * Create neutral behavior metrics for error scenarios
     */
    private createNeutralBehaviorMetrics(): BehaviorMetrics {
        return {
            requestInterval: 2000, // Neutral 2-second interval
            navigationPattern: [],
            timingConsistency: 0.5, // Neutral consistency
            humanLikeScore: 0.5, // Neutral human-like score
            sessionDuration: 0,
        };
    }
}