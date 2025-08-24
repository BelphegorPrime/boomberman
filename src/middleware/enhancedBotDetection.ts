import type { Request, Response, NextFunction } from 'express';
import { HTTPFingerprintAnalyzer } from '../detection/analyzers/HTTPFingerprintAnalyzer.js';
import { BehaviorAnalyzer } from '../detection/analyzers/BehaviorAnalyzer.js';
import { GeoAnalyzer } from '../detection/analyzers/GeoAnalyzer.js';
import { ThreatScoringEngine } from '../detection/ThreatScoringEngine.js';
import { logThreat } from '../utils/logger/logger.js';
import { generateFaultyResponse } from '../utils/generateFaultyResponse.js';
import {
    getDetectionLogger,
    createPerformanceMetrics,
    type CorrelationContext,
    type PerformanceMetrics as DetectionPerformanceMetrics
} from '../utils/logger/detectionLogger.js';
import type {
    DetectionResult,
    DetectionConfig,
    GeoLocation,
} from '../detection/types/index.js';
import { DEFAULT_DETECTION_CONFIG } from '../detection/types/Configuration.js';

/**
 * Performance monitoring interface for tracking middleware execution
 */
interface PerformanceMetrics {
    totalTime: number;
    fingerprintTime: number;
    behaviorTime: number;
    geoTime: number;
    scoringTime: number;
    timeoutOccurred: boolean;
}

/**
 * Enhanced bot detection middleware that orchestrates all analyzers
 */
export class EnhancedBotDetectionMiddleware {
    private readonly httpAnalyzer: HTTPFingerprintAnalyzer;
    private readonly behaviorAnalyzer: BehaviorAnalyzer;
    private readonly geoAnalyzer: GeoAnalyzer;
    private readonly scoringEngine: ThreatScoringEngine;
    private readonly config: DetectionConfig;
    private readonly maxProcessingTime: number = 50; // 50ms timeout

    constructor(config: DetectionConfig = DEFAULT_DETECTION_CONFIG) {
        this.config = config;

        this.httpAnalyzer = new HTTPFingerprintAnalyzer(config.fingerprinting);
        this.behaviorAnalyzer = new BehaviorAnalyzer(config.behavioral);
        this.geoAnalyzer = new GeoAnalyzer(config.geographic);
        this.scoringEngine = new ThreatScoringEngine(config.scoringWeights);

        // Initialize GeoAnalyzer asynchronously
        this.initializeGeoAnalyzer();
    }

    /**
     * Initialize GeoAnalyzer asynchronously
     */
    private async initializeGeoAnalyzer(): Promise<void> {
        try {
            await this.geoAnalyzer.initialize();
        } catch (error) {
            console.warn('Failed to initialize GeoAnalyzer, geographic analysis will be disabled:', error);
        }
    }

    /**
     * Main middleware function that orchestrates all analyzers
     */
    middleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        // Skip if detection is disabled
        if (!this.config.enabled) {
            return next();
        }

        const startTime = process.hrtime.bigint();
        const startCpuUsage = process.cpuUsage();
        const logger = getDetectionLogger();

        // Create correlation context for request tracing
        const context = logger.createCorrelationContext(req);

        // Log detection start
        logger.logDetectionStart(context, req);

        const ip = req.realIp || req.socket.remoteAddress || 'unknown';
        const userAgent = req.headers['user-agent'] || '';

        try {
            // Check whitelist first for performance
            if (this.isWhitelisted(ip, userAgent)) {
                return next();
            }

            // Perform analysis with timeout protection
            const result = await this.performAnalysisWithTimeout(req, ip);

            // Calculate detailed performance metrics
            const totalTime = Number(process.hrtime.bigint() - startTime) / 1_000_000;
            const timingBreakdown = result.metadata.detectorVersions?.timingBreakdown as any;

            const performanceMetrics = createPerformanceMetrics(
                totalTime,
                timingBreakdown?.fingerprint || 0,
                timingBreakdown?.behavior || 0,
                timingBreakdown?.geo || 0,
                timingBreakdown?.scoring || 0,
                startCpuUsage
            );

            // Add detection metadata to request for downstream middleware
            req.detectionResult = result;
            req.detectionMetrics = this.calculatePerformanceMetrics(startTime, result.metadata.processingTime);
            req.correlationId = context.correlationId;

            // Log detection completion
            logger.logDetectionComplete(context, result, performanceMetrics, req);

            // Handle suspicious requests based on score
            if (result.isSuspicious) {
                return this.handleSuspiciousRequest(req, res, result, next, context);
            }

            // Continue to next middleware for legitimate requests
            next();

        } catch (error) {
            const detectionError = error instanceof Error ? error : new Error('Unknown detection error');

            // Log error with correlation context
            logger.logDetectionError(context, detectionError, req, 'enhancedBotDetection');

            // Add error metadata to request
            req.detectionError = detectionError.message;
            req.correlationId = context.correlationId;

            // Create fallback detection result
            req.detectionResult = this.createFallbackResult(req, ip);
            req.detectionMetrics = this.calculatePerformanceMetrics(startTime, 0);

            // Continue with request processing
            next();
        }
    };

    /**
     * Perform comprehensive analysis with timeout protection
     */
    private async performAnalysisWithTimeout(req: Request, ip: string): Promise<DetectionResult> {
        const analysisPromise = this.performAnalysis(req, ip);
        const timeoutPromise = this.createTimeoutPromise();

        try {
            return await Promise.race([analysisPromise, timeoutPromise]);
        } catch (error) {
            if (error instanceof Error && error.message === 'Analysis timeout') {
                // Return fallback result on timeout
                return this.createFallbackResult(req, ip);
            }
            throw error;
        }
    }

    /**
     * Perform comprehensive bot detection analysis
     */
    private async performAnalysis(req: Request, ip: string): Promise<DetectionResult> {
        const analysisStartTime = process.hrtime.bigint();

        // Run HTTP fingerprinting analysis
        const fingerprintStartTime = process.hrtime.bigint();
        const fingerprint = this.httpAnalyzer.analyze(req);
        const fingerprintTime = Number(process.hrtime.bigint() - fingerprintStartTime) / 1_000_000;

        // Run behavioral analysis
        const behaviorStartTime = process.hrtime.bigint();
        const behavior = this.behaviorAnalyzer.analyze(ip, req);
        const behaviorTime = Number(process.hrtime.bigint() - behaviorStartTime) / 1_000_000;

        // Run geographic analysis
        const geoStartTime = process.hrtime.bigint();
        let geo: GeoLocation;
        try {
            geo = await this.geoAnalyzer.analyze(ip);
        } catch (error) {
            // Fallback to default geo location if analysis fails
            geo = {
                country: 'unknown',
                region: 'unknown',
                city: 'unknown',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 0,
                organization: 'unknown',
            };
        }
        const geoTime = Number(process.hrtime.bigint() - geoStartTime) / 1_000_000;

        // Calculate threat score
        const scoringStartTime = process.hrtime.bigint();
        const result = this.scoringEngine.calculateScore(fingerprint, behavior, geo);
        const scoringTime = Number(process.hrtime.bigint() - scoringStartTime) / 1_000_000;

        // Add timing metadata
        const totalTime = Number(process.hrtime.bigint() - analysisStartTime) / 1_000_000;
        result.metadata.processingTime = totalTime;
        result.metadata.detectorVersions = {
            ...result.metadata.detectorVersions,
            enhancedBotDetection: '1.0.0',
            timingBreakdown: {
                fingerprint: fingerprintTime,
                behavior: behaviorTime,
                geo: geoTime,
                scoring: scoringTime,
            },
        };

        return result;
    }

    /**
     * Create timeout promise for analysis operations
     */
    private createTimeoutPromise(): Promise<never> {
        return new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error('Analysis timeout'));
            }, this.maxProcessingTime);
        });
    }

    /**
     * Create fallback detection result when analysis times out
     */
    private createFallbackResult(req: Request, ip: string): DetectionResult {
        const userAgent = req.headers['user-agent'] || '';

        // Basic fallback analysis - just check user agent
        const isSuspiciousUA = this.config.fingerprinting.suspiciousPatterns.some(pattern =>
            pattern.test(userAgent)
        );

        const isAutomationUA = this.config.fingerprinting.automationSignatures.some(pattern =>
            pattern.test(userAgent)
        );

        const suspicionScore = isAutomationUA ? 80 : isSuspiciousUA ? 40 : 10;

        return {
            isSuspicious: suspicionScore >= this.config.thresholds.suspicious,
            suspicionScore,
            confidence: 0.3, // Low confidence due to timeout
            reasons: [{
                category: 'fingerprint',
                severity: isAutomationUA ? 'high' : isSuspiciousUA ? 'medium' : 'low',
                description: 'Fallback analysis due to timeout - basic user-agent check only',
                score: suspicionScore,
            }],
            fingerprint: `fallback-${userAgent.substring(0, 16)}`,
            metadata: {
                timestamp: Date.now(),
                processingTime: this.maxProcessingTime,
                detectorVersions: {
                    enhancedBotDetection: '1.0.0-fallback',
                },
                timeoutOccurred: true,
            },
        };
    }

    /**
     * Check if request should be whitelisted
     */
    private isWhitelisted(ip: string, userAgent: string): boolean {
        // Normalize IP address (remove IPv6 prefix if present)
        const normalizedIp = ip.replace(/^::ffff:/, '');

        // Check IP whitelist
        if (this.config.whitelist.ips.includes(normalizedIp) || this.config.whitelist.ips.includes(ip)) {
            return true;
        }

        // Check user-agent whitelist
        return this.config.whitelist.userAgents.some(pattern => pattern.test(userAgent));
    }

    /**
     * Handle suspicious requests based on threat score
     */
    private handleSuspiciousRequest(
        req: Request,
        res: Response,
        result: DetectionResult,
        next: NextFunction,
        context: CorrelationContext
    ): void {
        const logger = getDetectionLogger();
        const userAgent = req.headers['user-agent'] || '';

        // Set response headers with detection information
        res.setHeader('X-Detection-Score', result.suspicionScore.toString());
        res.setHeader('X-Detection-Confidence', result.confidence.toString());
        res.setHeader('X-Detection-Fingerprint', result.fingerprint);
        res.setHeader('X-Correlation-ID', context.correlationId);

        if (result.suspicionScore >= this.config.thresholds.highRisk) {
            // High risk - generate faulty response
            logger.logThreatAction(context, 'BLOCKED', result, req);

            logThreat('HIGH_RISK_BOT_DETECTED', req.path, userAgent, {
                score: result.suspicionScore,
                confidence: result.confidence,
                reasons: result.reasons.map(r => r.description),
                fingerprint: result.fingerprint,
                correlationId: context.correlationId,
            });

            generateFaultyResponse(res);
        } else {
            // Medium risk - apply rate limiting by setting flag for downstream middleware
            logger.logThreatAction(context, 'RATE_LIMITED', result, req);

            logThreat('SUSPICIOUS_BOT_DETECTED', req.path, userAgent, {
                score: result.suspicionScore,
                confidence: result.confidence,
                reasons: result.reasons.map(r => r.description),
                fingerprint: result.fingerprint,
                correlationId: context.correlationId,
            });

            // Set flag for tarpit middleware to apply delays
            req.suspiciousRequest = true;
            req.suspicionScore = result.suspicionScore;

            // Continue to next middleware (likely tarpit)
            next();
            return;
        }
    }

    /**
     * Log detection results for monitoring and analysis (legacy method - now handled by DetectionLogger)
     */
    private logDetectionResult(ip: string, userAgent: string, path: string, result: DetectionResult): void {
        // This method is now primarily for backward compatibility
        // Main logging is handled by DetectionLogger in the middleware method

        if (result.isSuspicious && process.env.NODE_ENV === 'development') {
            console.log(`[Enhanced Detection] Suspicious request from ${ip}:`, {
                path,
                score: result.suspicionScore,
                confidence: result.confidence,
                processingTime: result.metadata.processingTime,
                reasons: result.reasons.length,
                fingerprint: result.fingerprint,
            });
        }
    }

    /**
     * Calculate performance metrics for monitoring
     */
    private calculatePerformanceMetrics(startTime: bigint, processingTime: number): PerformanceMetrics {
        const totalTime = Number(process.hrtime.bigint() - startTime) / 1_000_000;

        return {
            totalTime,
            fingerprintTime: 0, // Will be populated from metadata if available
            behaviorTime: 0,
            geoTime: 0,
            scoringTime: 0,
            timeoutOccurred: processingTime >= this.maxProcessingTime,
        };
    }

    /**
     * Update configuration at runtime
     */
    updateConfig(newConfig: Partial<DetectionConfig>): void {
        Object.assign(this.config, newConfig);

        // Update scoring weights if provided
        if (newConfig.scoringWeights) {
            this.scoringEngine.updateWeights(newConfig.scoringWeights);
        }
    }

    /**
     * Get current configuration
     */
    getConfig(): DetectionConfig {
        return { ...this.config };
    }

    /**
     * Get performance statistics
     */
    getPerformanceStats(): { averageProcessingTime: number; timeoutRate: number } {
        // This would be implemented with actual metrics collection
        // For now, return placeholder values
        return {
            averageProcessingTime: 25, // ms
            timeoutRate: 0.01, // 1%
        };
    }
}

// Create singleton instance with default configuration
const enhancedBotDetection = new EnhancedBotDetectionMiddleware();

// Export the middleware function
export const enhancedBotDetectionMiddleware = enhancedBotDetection.middleware;

// Export configuration for external usage
export { DEFAULT_DETECTION_CONFIG };