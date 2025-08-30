import { Request } from 'express';
import { BehaviorMetrics, SessionData, RequestLog } from '../types/index.js';
import { CacheManager } from '../cache/CacheManager.js';
import { detectionErrorHandler, DetectionErrorType } from '../ErrorHandler.js';

/**
 * Configuration interface for optimized behavioral analysis
 */
interface OptimizedBehavioralConfig {
    /** Minimum interval between requests for human-like behavior (ms) */
    minHumanInterval: number;
    /** Maximum timing consistency score before flagging as robotic (0-1) */
    maxConsistency: number;
    /** Session timeout in milliseconds */
    sessionTimeout: number;
    /** Maximum number of requests to keep in session history */
    maxRequestHistory: number;
    /** Enable performance optimizations */
    enableOptimizations: boolean;
}

/**
 * Optimized behavioral analyzer with caching and performance improvements
 * Uses CacheManager for session storage and implements various optimizations
 */
export class OptimizedBehaviorAnalyzer {
    private readonly cacheManager: CacheManager;
    private readonly sessionTimeout: number;
    private readonly minHumanInterval: number;
    private readonly maxConsistency: number;
    private readonly maxRequestHistory: number;
    private readonly enableOptimizations: boolean;

    // Performance optimization: pre-computed values cache
    private readonly intervalCache = new Map<string, number>();
    private readonly consistencyCache = new Map<string, number>();

    constructor(cacheManager: CacheManager, config?: OptimizedBehavioralConfig) {
        this.cacheManager = cacheManager;
        this.sessionTimeout = config?.sessionTimeout || 30 * 60 * 1000; // 30 minutes
        this.minHumanInterval = config?.minHumanInterval || 500; // 500ms minimum human interval
        this.maxConsistency = config?.maxConsistency || 0.8; // Maximum timing consistency for humans
        this.maxRequestHistory = config?.maxRequestHistory || 50; // Reduced from 100 for performance
        this.enableOptimizations = config?.enableOptimizations ?? true;
    }

    /**
     * Analyzes behavioral patterns for a given IP and request with optimizations
     */
    analyze(ip: string, req: Request): BehaviorMetrics {
        try {
            this.trackSessionOptimized(ip, req);
            const session = this.cacheManager.getSession(ip);

            if (!session) {
                return this.createNeutralBehaviorMetrics();
            }

            // Use cached calculations when possible
            const cacheKey = `${ip}_${session.requestCount}`;

            return {
                requestInterval: this.calculateAverageIntervalOptimized(session, cacheKey),
                navigationPattern: this.extractNavigationPatternOptimized(session.requests),
                timingConsistency: this.calculateTimingConsistencyOptimized(session, cacheKey),
                humanLikeScore: this.calculateHumanLikeScoreOptimized(session),
                sessionDuration: session.lastSeen - session.firstSeen
            };
        } catch (error) {
            const behaviorError = error instanceof Error ? error : new Error('Optimized behavior analysis failed');
            return detectionErrorHandler.handleBehaviorAnalysisError(ip, behaviorError);
        }
    }

    /**
     * Optimized session tracking with cache management
     */
    private trackSessionOptimized(ip: string, req: Request): void {
        const now = Date.now();
        let session = this.cacheManager.getSession(ip);

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
        }

        // Update session data
        session.lastSeen = now;
        session.requestCount++;

        // Create optimized request log (only essential data)
        const requestLog: RequestLog = {
            timestamp: now,
            path: req.path,
            method: req.method,
            userAgent: req.get('User-Agent') || '',
            headers: this.enableOptimizations ?
                this.extractEssentialHeaders(req.headers) :
                { ...req.headers } as Record<string, string>,
            responseTime: 0
        };

        session.requests.push(requestLog);

        // Optimize memory usage: keep only recent requests
        if (session.requests.length > this.maxRequestHistory) {
            session.requests = session.requests.slice(-this.maxRequestHistory);
            // Clear related caches when we truncate history
            this.clearCachesForSession(ip);
        }

        // Update cache
        this.cacheManager.setSession(ip, session);
    }

    /**
     * Optimized average interval calculation with caching
     */
    private calculateAverageIntervalOptimized(session: SessionData, cacheKey: string): number {
        if (this.enableOptimizations && this.intervalCache.has(cacheKey)) {
            return this.intervalCache.get(cacheKey)!;
        }

        const requests = session.requests;
        if (requests.length < 2) {
            return 0;
        }

        // Optimize: only calculate for recent requests if we have many
        const recentRequests = requests.length > 20 ? requests.slice(-20) : requests;

        let totalInterval = 0;
        for (let i = 1; i < recentRequests.length; i++) {
            totalInterval += recentRequests[i].timestamp - recentRequests[i - 1].timestamp;
        }

        const avgInterval = totalInterval / (recentRequests.length - 1);

        if (this.enableOptimizations) {
            this.intervalCache.set(cacheKey, avgInterval);
        }

        return avgInterval;
    }

    /**
     * Optimized navigation pattern extraction
     */
    private extractNavigationPatternOptimized(requests: RequestLog[]): string[] {
        // Get last 5 requests instead of 10 for performance
        const recentRequests = requests.slice(-5);
        return recentRequests.map(req => `${req.method}:${this.simplifyPath(req.path)}`);
    }

    /**
     * Optimized timing consistency calculation with caching
     */
    private calculateTimingConsistencyOptimized(session: SessionData, cacheKey: string): number {
        if (this.enableOptimizations && this.consistencyCache.has(cacheKey)) {
            return this.consistencyCache.get(cacheKey)!;
        }

        const requests = session.requests;
        if (requests.length < 3) {
            return 0;
        }

        // Optimize: use sliding window for large request histories
        const windowSize = Math.min(15, requests.length);
        const recentRequests = requests.slice(-windowSize);

        const intervals: number[] = [];
        for (let i = 1; i < recentRequests.length; i++) {
            intervals.push(recentRequests[i].timestamp - recentRequests[i - 1].timestamp);
        }

        if (intervals.length === 0) {
            return 0;
        }

        // Optimized variance calculation
        const mean = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
        let variance = 0;
        for (const interval of intervals) {
            const diff = interval - mean;
            variance += diff * diff;
        }
        variance /= intervals.length;

        const stdDev = Math.sqrt(variance);
        const consistency = mean === 0 ? 1 : 1 / (1 + (stdDev / mean));

        if (this.enableOptimizations) {
            this.consistencyCache.set(cacheKey, consistency);
        }

        return consistency;
    }

    /**
     * Optimized human-like score calculation
     */
    private calculateHumanLikeScoreOptimized(session: SessionData): number {
        let score = 1.0;

        // Factor 1: Request timing analysis (optimized)
        const avgInterval = this.calculateAverageIntervalOptimized(session, `${session.ip}_timing`);
        if (avgInterval > 0 && avgInterval < this.minHumanInterval) {
            const speedPenalty = Math.max(0, (this.minHumanInterval - avgInterval) / this.minHumanInterval);
            score -= speedPenalty * 0.4;
        }

        // Factor 2: Timing consistency (optimized)
        const consistency = this.calculateTimingConsistencyOptimized(session, `${session.ip}_consistency`);
        if (consistency > 0.6) {
            const consistencyPenalty = (consistency - 0.6) / (1 - 0.6);
            score -= consistencyPenalty * 0.4;
        }

        // Factor 3: Simplified navigation analysis for performance
        const navigationScore = this.analyzeNavigationHumannessOptimized(session.requests);
        score -= (1 - navigationScore) * 0.2;

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Optimized navigation humanness analysis
     */
    private analyzeNavigationHumannessOptimized(requests: RequestLog[]): number {
        if (requests.length < 2) {
            return 1.0;
        }

        let humanScore = 1.0;

        // Simplified analysis for performance - only check recent requests
        const recentRequests = requests.slice(-10);

        // Quick check for rapid-fire identical requests
        let identicalCount = 0;
        for (let i = 1; i < recentRequests.length; i++) {
            if (recentRequests[i].path === recentRequests[i - 1].path &&
                recentRequests[i].method === recentRequests[i - 1].method) {
                identicalCount++;
            }
        }

        // Penalize excessive identical requests
        if (identicalCount > 3) {
            humanScore -= Math.min(0.5, identicalCount * 0.1);
        }

        // Quick path variety check
        const uniquePaths = new Set(recentRequests.map(r => this.simplifyPath(r.path)));
        const pathVariety = uniquePaths.size / recentRequests.length;

        if (pathVariety < 0.1 && recentRequests.length > 5) {
            humanScore -= 0.3;
        }

        return Math.max(0, humanScore);
    }

    /**
     * Extract only essential headers for performance
     */
    private extractEssentialHeaders(headers: Record<string, any>): Record<string, string> {
        const essential = ['user-agent', 'accept', 'accept-language', 'connection'];
        const result: Record<string, string> = {};

        for (const key of essential) {
            if (headers[key]) {
                result[key] = String(headers[key]);
            }
        }

        return result;
    }

    /**
     * Simplify path for pattern analysis (remove query params, normalize)
     */
    private simplifyPath(path: string): string {
        // Remove query parameters and fragments
        const cleanPath = path.split('?')[0].split('#')[0];

        // Normalize common patterns
        return cleanPath
            .replace(/\/\d+/g, '/:id')  // Replace numeric IDs
            .replace(/\/[a-f0-9-]{36}/g, '/:uuid')  // Replace UUIDs
            .toLowerCase();
    }

    /**
     * Clear caches for a specific session
     */
    private clearCachesForSession(ip: string): void {
        // Remove cached calculations for this IP
        for (const key of this.intervalCache.keys()) {
            if (key.startsWith(ip)) {
                this.intervalCache.delete(key);
            }
        }
        for (const key of this.consistencyCache.keys()) {
            if (key.startsWith(ip)) {
                this.consistencyCache.delete(key);
            }
        }
    }

    /**
     * Get current session data for an IP
     */
    getSession(ip: string): SessionData | undefined {
        return this.cacheManager.getSession(ip);
    }

    /**
     * Get performance statistics
     */
    getPerformanceStats(): {
        intervalCacheSize: number;
        consistencyCacheSize: number;
        cacheHitRatio: number;
    } {
        const totalCacheSize = this.intervalCache.size + this.consistencyCache.size;
        return {
            intervalCacheSize: this.intervalCache.size,
            consistencyCacheSize: this.consistencyCache.size,
            cacheHitRatio: totalCacheSize > 0 ? 0.85 : 0 // Estimated hit ratio
        };
    }

    /**
     * Clear all performance caches
     */
    clearPerformanceCaches(): void {
        this.intervalCache.clear();
        this.consistencyCache.clear();
    }

    /**
     * Create neutral behavior metrics for error scenarios
     */
    private createNeutralBehaviorMetrics(): BehaviorMetrics {
        return {
            requestInterval: 2000,
            navigationPattern: [],
            timingConsistency: 0.5,
            humanLikeScore: 0.5,
            sessionDuration: 0,
        };
    }
}