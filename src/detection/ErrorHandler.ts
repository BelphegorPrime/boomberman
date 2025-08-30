import type { Request } from 'express';
import type {
    DetectionResult,
    HTTPFingerprint,
    BehaviorMetrics,
    GeoLocation,
    DetectionReason,
    DetectionMetadata,
} from './types/index.js';

/**
 * Error types for different detection components
 */
export enum DetectionErrorType {
    GEO_SERVICE_FAILURE = 'GEO_SERVICE_FAILURE',
    HTTP_FINGERPRINT_ERROR = 'HTTP_FINGERPRINT_ERROR',
    BEHAVIOR_ANALYSIS_ERROR = 'BEHAVIOR_ANALYSIS_ERROR',
    TLS_ANALYSIS_ERROR = 'TLS_ANALYSIS_ERROR',
    SCORING_ENGINE_ERROR = 'SCORING_ENGINE_ERROR',
    TIMEOUT_ERROR = 'TIMEOUT_ERROR',
    NETWORK_ERROR = 'NETWORK_ERROR',
    DATABASE_ERROR = 'DATABASE_ERROR',
    CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
}

/**
 * Circuit breaker states
 */
export enum CircuitBreakerState {
    CLOSED = 'CLOSED',
    OPEN = 'OPEN',
    HALF_OPEN = 'HALF_OPEN',
}

/**
 * Circuit breaker configuration
 */
interface CircuitBreakerConfig {
    failureThreshold: number;
    recoveryTimeout: number;
    monitoringPeriod: number;
    minimumRequests: number;
}

/**
 * Circuit breaker implementation for external services
 */
export class CircuitBreaker {
    private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
    private failureCount = 0;
    private lastFailureTime = 0;
    private requestCount = 0;
    private readonly config: CircuitBreakerConfig;

    constructor(config: Partial<CircuitBreakerConfig> = {}) {
        this.config = {
            failureThreshold: config.failureThreshold || 5,
            recoveryTimeout: config.recoveryTimeout || 60000, // 1 minute
            monitoringPeriod: config.monitoringPeriod || 300000, // 5 minutes
            minimumRequests: config.minimumRequests || 10,
        };
    }

    /**
     * Execute operation with circuit breaker protection
     */
    async execute<T>(operation: () => Promise<T>, fallback: T): Promise<T> {
        if (this.state === CircuitBreakerState.OPEN) {
            if (this.shouldAttemptReset()) {
                this.state = CircuitBreakerState.HALF_OPEN;
            } else {
                return fallback;
            }
        }

        try {
            this.requestCount++;
            const result = await operation();
            this.onSuccess();
            return result;
        } catch (error) {
            this.onFailure();
            return fallback;
        }
    }

    /**
     * Record successful operation
     */
    private onSuccess(): void {
        this.failureCount = 0;
        if (this.state === CircuitBreakerState.HALF_OPEN) {
            this.state = CircuitBreakerState.CLOSED;
        }
    }

    /**
     * Record failed operation
     */
    private onFailure(): void {
        this.failureCount++;
        this.lastFailureTime = Date.now();

        if (this.shouldOpenCircuit()) {
            this.state = CircuitBreakerState.OPEN;
        }
    }

    /**
     * Check if circuit should be opened
     */
    private shouldOpenCircuit(): boolean {
        return (
            this.requestCount >= this.config.minimumRequests &&
            this.failureCount >= this.config.failureThreshold
        );
    }

    /**
     * Check if circuit should attempt reset
     */
    private shouldAttemptReset(): boolean {
        return Date.now() - this.lastFailureTime >= this.config.recoveryTimeout;
    }

    /**
     * Get current circuit breaker state
     */
    getState(): CircuitBreakerState {
        return this.state;
    }

    /**
     * Get failure statistics
     */
    getStats(): {
        state: CircuitBreakerState;
        failureCount: number;
        requestCount: number;
        lastFailureTime: number;
    } {
        return {
            state: this.state,
            failureCount: this.failureCount,
            requestCount: this.requestCount,
            lastFailureTime: this.lastFailureTime,
        };
    }

    /**
     * Reset circuit breaker manually
     */
    reset(): void {
        this.state = CircuitBreakerState.CLOSED;
        this.failureCount = 0;
        this.requestCount = 0;
        this.lastFailureTime = 0;
    }
}

/**
 * Performance guard for timeout protection
 */
export class PerformanceGuard {
    private readonly maxProcessingTime: number;

    constructor(maxProcessingTime: number = 50) {
        this.maxProcessingTime = maxProcessingTime;
    }

    /**
     * Execute operation with timeout protection
     */
    async executeWithTimeout<T>(
        operation: () => Promise<T>,
        fallback: T,
        timeoutMs?: number
    ): Promise<T> {
        const timeout = timeoutMs || this.maxProcessingTime;

        try {
            return await Promise.race([
                operation(),
                this.createTimeoutPromise<T>(timeout),
            ]);
        } catch (error) {
            if (error instanceof Error && error.message === 'Operation timeout') {
                console.warn(`Operation timed out after ${timeout}ms, using fallback`);
                return fallback;
            }
            throw error;
        }
    }

    /**
     * Create timeout promise
     */
    private createTimeoutPromise<T>(timeoutMs: number): Promise<T> {
        return new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error('Operation timeout'));
            }, timeoutMs);
        });
    }
}

/**
 * Main error handler for detection system
 */
export class DetectionErrorHandler {
    private readonly geoCircuitBreaker: CircuitBreaker;
    private readonly performanceGuard: PerformanceGuard;
    private readonly errorCounts: Map<DetectionErrorType, number> = new Map();
    private readonly lastErrors: Map<DetectionErrorType, number> = new Map();

    constructor() {
        this.geoCircuitBreaker = new CircuitBreaker({
            failureThreshold: 3,
            recoveryTimeout: 30000, // 30 seconds
            minimumRequests: 5,
        });
        this.performanceGuard = new PerformanceGuard(50);
    }

    /**
     * Handle GeoIP service failures with circuit breaker
     */
    async handleGeoServiceFailure(ip: string): Promise<GeoLocation> {
        this.recordError(DetectionErrorType.GEO_SERVICE_FAILURE);

        return this.geoCircuitBreaker.execute(
            async () => {
                // This would be the actual geo service call
                throw new Error('Geo service unavailable');
            },
            this.createDefaultGeoLocation(ip)
        );
    }

    /**
     * Handle HTTP fingerprinting errors
     */
    handleFingerprintingError(req: Request, error: Error): HTTPFingerprint {
        this.recordError(DetectionErrorType.HTTP_FINGERPRINT_ERROR);
        console.warn('HTTP fingerprinting failed, using basic analysis:', error.message);

        return this.createBasicFingerprint(req);
    }

    /**
     * Handle behavioral analysis errors
     */
    handleBehaviorAnalysisError(ip: string, error: Error): BehaviorMetrics {
        this.recordError(DetectionErrorType.BEHAVIOR_ANALYSIS_ERROR);
        console.warn('Behavioral analysis failed, using neutral metrics:', error.message);

        return this.createNeutralBehaviorMetrics();
    }

    /**
     * Handle TLS analysis errors
     */
    handleTLSAnalysisError(error: Error): string | undefined {
        this.recordError(DetectionErrorType.TLS_ANALYSIS_ERROR);
        console.warn('TLS analysis failed:', error.message);

        return undefined; // No TLS fingerprint available
    }

    /**
     * Handle scoring engine errors
     */
    handleScoringEngineError(
        req: Request,
        ip: string,
        error: Error
    ): DetectionResult {
        this.recordError(DetectionErrorType.SCORING_ENGINE_ERROR);
        console.warn('Scoring engine failed, using fallback scoring:', error.message);

        return this.createFallbackDetectionResult(req, ip);
    }

    /**
     * Handle timeout errors
     */
    handleTimeoutError(req: Request, ip: string): DetectionResult {
        this.recordError(DetectionErrorType.TIMEOUT_ERROR);
        console.warn('Detection analysis timed out, using fallback result');

        return this.createTimeoutFallbackResult(req, ip);
    }

    /**
     * Execute operation with comprehensive error handling
     */
    async executeWithErrorHandling<T>(
        operation: () => Promise<T>,
        fallback: T,
        errorType: DetectionErrorType,
        timeoutMs?: number
    ): Promise<T> {
        try {
            return await this.performanceGuard.executeWithTimeout(
                operation,
                fallback,
                timeoutMs
            );
        } catch (error) {
            this.recordError(errorType);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            console.warn(`Operation failed (${errorType}):`, errorMessage);
            return fallback;
        }
    }

    /**
     * Create default geo location for failed lookups
     */
    private createDefaultGeoLocation(ip: string): GeoLocation {
        // Determine if IP is private/local for better defaults
        const isPrivate = this.isPrivateIP(ip);

        return {
            country: isPrivate ? 'local' : 'unknown',
            region: isPrivate ? 'local' : 'unknown',
            city: isPrivate ? 'local' : 'unknown',
            isVPN: false,
            isProxy: false,
            isHosting: false,
            isTor: false,
            riskScore: isPrivate ? 0 : 10, // Slight risk for unknown external IPs
            asn: 0,
            organization: isPrivate ? 'local' : 'unknown',
        };
    }

    /**
     * Create basic HTTP fingerprint for failed analysis
     */
    private createBasicFingerprint(req: Request): HTTPFingerprint {
        const userAgent = req.headers['user-agent'] || '';
        const hasCommonHeaders = !!(
            req.headers.accept &&
            req.headers['accept-language'] &&
            req.headers['accept-encoding']
        );

        // Basic bot detection patterns
        const botPatterns = [
            /bot/i,
            /crawler/i,
            /spider/i,
            /scraper/i,
            /curl/i,
            /wget/i,
            /python/i,
            /selenium/i,
            /puppeteer/i,
        ];

        const automationSignatures = botPatterns
            .filter(pattern => pattern.test(userAgent))
            .map(pattern => pattern.source.toLowerCase());

        return {
            headerSignature: this.generateBasicSignature(req.headers),
            missingHeaders: hasCommonHeaders ? [] : ['accept', 'accept-language', 'accept-encoding'],
            suspiciousHeaders: [],
            headerOrderScore: hasCommonHeaders ? 0.7 : 0.3,
            automationSignatures,
            tlsFingerprint: undefined,
        };
    }

    /**
     * Create neutral behavior metrics for failed analysis
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

    /**
     * Create fallback detection result for scoring engine failures
     */
    private createFallbackDetectionResult(req: Request, ip: string): DetectionResult {
        const userAgent = req.headers['user-agent'] || '';

        // Simple heuristic-based scoring
        let suspicionScore = 0;
        const reasons: DetectionReason[] = [];

        // Check for obvious bot indicators
        const botPatterns = [
            { pattern: /bot/i, score: 60, description: 'User-agent contains "bot"' },
            { pattern: /crawler/i, score: 70, description: 'User-agent contains "crawler"' },
            { pattern: /spider/i, score: 70, description: 'User-agent contains "spider"' },
            { pattern: /curl/i, score: 80, description: 'User-agent indicates curl' },
            { pattern: /wget/i, score: 80, description: 'User-agent indicates wget' },
            { pattern: /python/i, score: 75, description: 'User-agent indicates Python script' },
            { pattern: /selenium/i, score: 90, description: 'User-agent indicates Selenium automation' },
            { pattern: /puppeteer/i, score: 90, description: 'User-agent indicates Puppeteer automation' },
        ];

        for (const { pattern, score, description } of botPatterns) {
            if (pattern.test(userAgent)) {
                suspicionScore = Math.max(suspicionScore, score);
                reasons.push({
                    category: 'fingerprint',
                    severity: score > 80 ? 'high' : score > 60 ? 'medium' : 'low',
                    description,
                    score,
                });
                break; // Use highest matching pattern
            }
        }

        // Check for missing common headers
        const hasCommonHeaders = !!(
            req.headers.accept &&
            req.headers['accept-language'] &&
            req.headers['accept-encoding']
        );

        if (!hasCommonHeaders) {
            const penalty = 30;
            suspicionScore += penalty;
            reasons.push({
                category: 'fingerprint',
                severity: 'medium',
                description: 'Missing common browser headers',
                score: penalty,
            });
        }

        // Default to low suspicion if no indicators found
        if (suspicionScore === 0) {
            suspicionScore = 5;
            reasons.push({
                category: 'fingerprint',
                severity: 'low',
                description: 'Fallback analysis - no clear indicators',
                score: 5,
            });
        }

        const metadata: DetectionMetadata = {
            timestamp: Date.now(),
            processingTime: 1, // Minimal processing time for fallback
            detectorVersions: {
                fallbackDetection: '1.0.0',
            },
            fallbackReason: 'Scoring engine failure',
        };

        return {
            isSuspicious: suspicionScore >= 30,
            suspicionScore: Math.min(suspicionScore, 100),
            confidence: 0.3, // Low confidence for fallback
            reasons,
            fingerprint: `fallback-${this.generateBasicSignature(req.headers)}`,
            metadata,
        };
    }

    /**
     * Create timeout-specific fallback result
     */
    private createTimeoutFallbackResult(req: Request, ip: string): DetectionResult {
        const result = this.createFallbackDetectionResult(req, ip);

        // Modify for timeout scenario
        result.metadata.fallbackReason = 'Analysis timeout';
        result.metadata.timeoutOccurred = true;
        result.confidence = 0.2; // Even lower confidence for timeout

        // Add timeout-specific reason
        result.reasons.unshift({
            category: 'fingerprint',
            severity: 'low',
            description: 'Analysis timed out - using basic fallback detection',
            score: 10,
        });

        return result;
    }

    /**
     * Generate basic signature from headers
     */
    private generateBasicSignature(headers: Record<string, any>): string {
        const headerKeys = Object.keys(headers).sort();
        const signatureData = headerKeys.slice(0, 10).join('|'); // Use first 10 headers

        // Simple hash
        let hash = 0;
        for (let i = 0; i < signatureData.length; i++) {
            const char = signatureData.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }

        return `basic-${Math.abs(hash).toString(16)}`;
    }

    /**
     * Check if IP is private/local
     */
    private isPrivateIP(ip: string): boolean {
        if (ip === '127.0.0.1' || ip === '::1' || ip === 'unknown') {
            return true;
        }

        // Check IPv6 private ranges
        if (ip.includes(':')) {
            return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
        }

        const parts = ip.split('.');
        if (parts.length === 4) {
            const first = parseInt(parts[0]);
            const second = parseInt(parts[1]);

            return (
                first === 10 ||
                (first === 172 && second >= 16 && second <= 31) ||
                (first === 192 && second === 168)
            );
        }

        return false;
    }

    /**
     * Record error occurrence for monitoring
     */
    private recordError(errorType: DetectionErrorType): void {
        const currentCount = this.errorCounts.get(errorType) || 0;
        this.errorCounts.set(errorType, currentCount + 1);
        this.lastErrors.set(errorType, Date.now());
    }

    /**
     * Get error statistics
     */
    getErrorStats(): {
        errorCounts: Record<string, number>;
        lastErrors: Record<string, number>;
        circuitBreakerStates: Record<string, string>;
    } {
        const errorCounts: Record<string, number> = {};
        const lastErrors: Record<string, number> = {};

        for (const [type, count] of this.errorCounts.entries()) {
            errorCounts[type] = count;
        }

        for (const [type, timestamp] of this.lastErrors.entries()) {
            lastErrors[type] = timestamp;
        }

        return {
            errorCounts,
            lastErrors,
            circuitBreakerStates: {
                geoService: this.geoCircuitBreaker.getState(),
            },
        };
    }

    /**
     * Reset error statistics
     */
    resetErrorStats(): void {
        this.errorCounts.clear();
        this.lastErrors.clear();
        this.geoCircuitBreaker.reset();
    }

    /**
     * Get circuit breaker for geo service
     */
    getGeoCircuitBreaker(): CircuitBreaker {
        return this.geoCircuitBreaker;
    }

    /**
     * Check if system is healthy
     */
    isHealthy(): boolean {
        const geoStats = this.geoCircuitBreaker.getStats();

        // System is unhealthy if geo circuit breaker is open for too long
        if (geoStats.state === CircuitBreakerState.OPEN) {
            const timeSinceLastFailure = Date.now() - geoStats.lastFailureTime;
            if (timeSinceLastFailure > 300000) { // 5 minutes
                return false;
            }
        }

        // Check error rates
        const totalErrors = Array.from(this.errorCounts.values()).reduce((sum, count) => sum + count, 0);
        if (totalErrors > 100) { // Arbitrary threshold
            return false;
        }

        return true;
    }
}

// Export singleton instance
export const detectionErrorHandler = new DetectionErrorHandler();