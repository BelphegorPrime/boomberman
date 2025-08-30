import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import type { DetectionResult } from '../../detection/types/DetectionResult.js';
import type { DetectionAnalytics, ThreatSummary } from '../../detection/types/Analytics.js';
import { ensureDirExistence } from '../ensureDirExistence.js';
import { isTest } from '../isTest.js';

/**
 * Correlation ID for request tracing
 */
export interface CorrelationContext {
    correlationId: string;
    requestId: string;
    sessionId?: string;
    ip: string;
    userAgent: string;
    timestamp: number;
}

/**
 * Structured log entry for detection events
 */
export interface DetectionLogEntry {
    correlationId: string;
    requestId: string;
    timestamp: number;
    level: 'info' | 'warn' | 'error';
    event: string;
    ip: string;
    userAgent: string;
    path: string;
    method: string;
    detectionResult?: DetectionResult;
    performanceMetrics?: PerformanceMetrics;
    error?: string;
    metadata?: Record<string, unknown>;
}

/**
 * Performance metrics for detection operations
 */
export interface PerformanceMetrics {
    totalProcessingTime: number;
    fingerprintingTime: number;
    behaviorAnalysisTime: number;
    geoAnalysisTime: number;
    scoringTime: number;
    memoryUsage: NodeJS.MemoryUsage;
    cpuUsage?: NodeJS.CpuUsage;
}

/**
 * Configuration change audit entry
 */
export interface ConfigurationChangeEntry {
    timestamp: number;
    correlationId: string;
    changeType: 'THRESHOLD_UPDATE' | 'WEIGHT_UPDATE' | 'WHITELIST_UPDATE' | 'FEATURE_TOGGLE' | 'FULL_CONFIG_UPDATE';
    oldValue: any;
    newValue: any;
    changedBy: string;
    reason?: string;
    metadata?: Record<string, unknown>;
}

/**
 * False positive report for analysis and tuning
 */
export interface FalsePositiveReport {
    timestamp: number;
    correlationId: string;
    ip: string;
    userAgent: string;
    originalScore: number;
    originalReasons: string[];
    reportedBy: string;
    actualClassification: 'LEGITIMATE' | 'SUSPICIOUS' | 'MALICIOUS';
    feedback: string;
    metadata?: Record<string, unknown>;
}

/**
 * Enhanced detection reasoning with detailed breakdown
 */
export interface DetailedDetectionReasoning {
    overallScore: number;
    confidence: number;
    scoreBreakdown: {
        fingerprint: {
            score: number;
            weight: number;
            factors: Array<{
                factor: string;
                value: any;
                impact: number;
                description: string;
            }>;
        };
        behavioral: {
            score: number;
            weight: number;
            factors: Array<{
                factor: string;
                value: any;
                impact: number;
                description: string;
            }>;
        };
        geographic: {
            score: number;
            weight: number;
            factors: Array<{
                factor: string;
                value: any;
                impact: number;
                description: string;
            }>;
        };
        reputation: {
            score: number;
            weight: number;
            factors: Array<{
                factor: string;
                value: any;
                impact: number;
                description: string;
            }>;
        };
    };
    riskFactors: string[];
    mitigatingFactors: string[];
    recommendedAction: 'ALLOW' | 'MONITOR' | 'RATE_LIMIT' | 'BLOCK' | 'BAN';
}

/**
 * Enhanced logger for bot detection system with structured logging and metrics
 */
export class DetectionLogger {
    private readonly logFile: string;
    private readonly metricsFile: string;
    private readonly auditLogFile: string;
    private logStream: fs.WriteStream;
    private metricsStream: fs.WriteStream;
    private auditLogStream: fs.WriteStream;
    private analytics: DetectionAnalytics;
    private threatSummaries: Map<string, ThreatSummary>;
    private performanceBuffer: PerformanceMetrics[];
    private readonly maxBufferSize = 1000;
    private configurationHistory: ConfigurationChangeEntry[] = [];
    private falsePositiveReports: FalsePositiveReport[] = [];

    constructor() {
        // Use test data directory when in test mode
        const dataDir = isTest
            ? path.resolve(process.cwd(), 'test/data')
            : process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
        this.logFile = path.join(dataDir, 'detection.log');
        this.metricsFile = path.join(dataDir, 'detection-metrics.log');
        this.auditLogFile = path.join(dataDir, 'detection-audit.log');

        ensureDirExistence(this.logFile);
        ensureDirExistence(this.metricsFile);
        ensureDirExistence(this.auditLogFile);

        this.logStream = fs.createWriteStream(this.logFile, { flags: 'a' });
        this.metricsStream = fs.createWriteStream(this.metricsFile, { flags: 'a' });
        this.auditLogStream = fs.createWriteStream(this.auditLogFile, { flags: 'a' });

        this.analytics = this.initializeAnalytics();
        this.threatSummaries = new Map();
        this.performanceBuffer = [];

        // Graceful shutdown handling
        process.on('SIGINT', () => this.close());
        process.on('SIGTERM', () => this.close());
    }

    /**
     * Create correlation context for request tracing
     */
    createCorrelationContext(req: any): CorrelationContext {
        return {
            correlationId: randomUUID(),
            requestId: req.id || randomUUID(),
            sessionId: req.sessionID,
            ip: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown',
            timestamp: Date.now(),
        };
    }

    /**
     * Log detection analysis start
     */
    logDetectionStart(context: CorrelationContext, req: any): void {
        const entry: DetectionLogEntry = {
            correlationId: context.correlationId,
            requestId: context.requestId,
            timestamp: context.timestamp,
            level: 'info',
            event: 'DETECTION_START',
            ip: context.ip,
            userAgent: context.userAgent,
            path: req.path || req.url || 'unknown',
            method: req.method || 'unknown',
            metadata: {
                headers: this.sanitizeHeaders(req.headers),
                query: req.query,
                sessionId: context.sessionId,
            },
        };

        this.writeLogEntry(entry);
        this.analytics.totalRequests++;
    }

    /**
     * Log detection analysis completion with detailed reasoning
     */
    logDetectionComplete(
        context: CorrelationContext,
        result: DetectionResult,
        metrics: PerformanceMetrics,
        req: any
    ): void {
        // Generate detailed reasoning for comprehensive analysis
        const detailedReasoning = this.generateDetailedReasoning(result);

        const entry: DetectionLogEntry = {
            correlationId: context.correlationId,
            requestId: context.requestId,
            timestamp: Date.now(),
            level: result.isSuspicious ? 'warn' : 'info',
            event: result.isSuspicious ? 'SUSPICIOUS_REQUEST_DETECTED' : 'LEGITIMATE_REQUEST_PROCESSED',
            ip: context.ip,
            userAgent: context.userAgent,
            path: req.path || req.url || 'unknown',
            method: req.method || 'unknown',
            detectionResult: result,
            performanceMetrics: metrics,
            metadata: {
                processingTime: result.metadata.processingTime,
                confidence: result.confidence,
                reasonCount: result.reasons.length,
                detailedReasoning,
                // SIEM-compatible fields
                severity: this.calculateSeverityLevel(result.suspicionScore),
                category: 'security.detection',
                source: 'enhanced-bot-detection',
                version: '1.0.0',
                // Additional context for analysis
                requestSize: req.headers?.['content-length'] || 0,
                referer: req.headers?.['referer'] || 'none',
                acceptLanguage: req.headers?.['accept-language'] || 'none',
                acceptEncoding: req.headers?.['accept-encoding'] || 'none',
            },
        };

        this.writeLogEntry(entry);
        this.updateAnalytics(result, metrics, context.ip);
        this.updateThreatSummary(context.ip, result);
        this.recordPerformanceMetrics(metrics);
    }

    /**
     * Log detection error
     */
    logDetectionError(
        context: CorrelationContext,
        error: Error,
        req: any,
        component?: string
    ): void {
        const entry: DetectionLogEntry = {
            correlationId: context.correlationId,
            requestId: context.requestId,
            timestamp: Date.now(),
            level: 'error',
            event: 'DETECTION_ERROR',
            ip: context.ip,
            userAgent: context.userAgent,
            path: req.path || req.url || 'unknown',
            method: req.method || 'unknown',
            error: error.message,
            metadata: {
                component,
                stack: error.stack,
                errorName: error.name,
            },
        };

        this.writeLogEntry(entry);
    }

    /**
     * Log threat action taken (ban, tarpit, etc.)
     */
    logThreatAction(
        context: CorrelationContext,
        action: 'BANNED' | 'TARPITTED' | 'RATE_LIMITED' | 'BLOCKED',
        result: DetectionResult,
        req: any
    ): void {
        const entry: DetectionLogEntry = {
            correlationId: context.correlationId,
            requestId: context.requestId,
            timestamp: Date.now(),
            level: 'warn',
            event: `THREAT_ACTION_${action}`,
            ip: context.ip,
            userAgent: context.userAgent,
            path: req.path || req.url || 'unknown',
            method: req.method || 'unknown',
            detectionResult: result,
            metadata: {
                action,
                suspicionScore: result.suspicionScore,
                confidence: result.confidence,
                primaryReasons: result.reasons
                    .filter(r => r.severity === 'high')
                    .map(r => r.description),
            },
        };

        this.writeLogEntry(entry);
        this.analytics.blockedRequests++;
    }

    /**
     * Log performance metrics summary
     */
    logPerformanceSummary(): void {
        if (this.performanceBuffer.length === 0) return;

        const summary = this.calculatePerformanceSummary();
        const entry = {
            timestamp: Date.now(),
            event: 'PERFORMANCE_SUMMARY',
            metrics: summary,
            sampleSize: this.performanceBuffer.length,
        };

        this.writeMetricsEntry(entry);
        this.performanceBuffer = []; // Clear buffer after logging
    }

    /**
     * Get current analytics data
     */
    getAnalytics(): DetectionAnalytics {
        return {
            ...this.analytics,
            topThreats: Array.from(this.threatSummaries.values())
                .sort((a, b) => b.averageScore - a.averageScore)
                .slice(0, 10),
        };
    }

    /**
     * Reset analytics (useful for testing)
     */
    resetAnalytics(): void {
        this.analytics = this.initializeAnalytics();
        this.threatSummaries.clear();
        this.performanceBuffer = [];
    }

    /**
     * Log configuration changes for audit purposes
     */
    logConfigurationChange(
        correlationId: string,
        changeType: ConfigurationChangeEntry['changeType'],
        oldValue: any,
        newValue: any,
        changedBy: string,
        reason?: string,
        metadata?: Record<string, unknown>
    ): void {
        const entry: ConfigurationChangeEntry = {
            timestamp: Date.now(),
            correlationId,
            changeType,
            oldValue,
            newValue,
            changedBy,
            reason,
            metadata,
        };

        this.configurationHistory.push(entry);

        // Write to audit log
        const auditEntry = {
            timestamp: entry.timestamp,
            level: 'info',
            event: 'CONFIGURATION_CHANGE',
            correlationId,
            changeType,
            changedBy,
            reason,
            changes: {
                old: oldValue,
                new: newValue,
            },
            metadata,
        };

        this.writeAuditEntry(auditEntry);
    }

    /**
     * Report false positive for analysis and system tuning
     */
    reportFalsePositive(
        correlationId: string,
        ip: string,
        userAgent: string,
        originalScore: number,
        originalReasons: string[],
        reportedBy: string,
        actualClassification: FalsePositiveReport['actualClassification'],
        feedback: string,
        metadata?: Record<string, unknown>
    ): void {
        const report: FalsePositiveReport = {
            timestamp: Date.now(),
            correlationId,
            ip,
            userAgent,
            originalScore,
            originalReasons,
            reportedBy,
            actualClassification,
            feedback,
            metadata,
        };

        this.falsePositiveReports.push(report);

        // Update analytics
        if (actualClassification === 'LEGITIMATE') {
            this.analytics.falsePositives++;
        }

        // Log the false positive report
        const entry: DetectionLogEntry = {
            correlationId,
            requestId: correlationId,
            timestamp: Date.now(),
            level: 'warn',
            event: 'FALSE_POSITIVE_REPORTED',
            ip,
            userAgent,
            path: 'unknown',
            method: 'unknown',
            metadata: {
                originalScore,
                originalReasons,
                reportedBy,
                actualClassification,
                feedback,
                ...metadata,
            },
        };

        this.writeLogEntry(entry);
    }

    /**
     * Generate detailed reasoning breakdown for comprehensive analysis
     */
    private generateDetailedReasoning(result: DetectionResult): DetailedDetectionReasoning {
        // Extract score breakdown from reasons
        const fingerprintFactors = result.reasons
            .filter(r => r.category === 'fingerprint')
            .map(r => ({
                factor: r.description,
                value: r.score,
                impact: r.score,
                description: `${r.severity} severity: ${r.description}`,
            }));

        const behavioralFactors = result.reasons
            .filter(r => r.category === 'behavioral')
            .map(r => ({
                factor: r.description,
                value: r.score,
                impact: r.score,
                description: `${r.severity} severity: ${r.description}`,
            }));

        const geographicFactors = result.reasons
            .filter(r => r.category === 'geographic')
            .map(r => ({
                factor: r.description,
                value: r.score,
                impact: r.score,
                description: `${r.severity} severity: ${r.description}`,
            }));

        const reputationFactors = result.reasons
            .filter(r => r.category === 'reputation')
            .map(r => ({
                factor: r.description,
                value: r.score,
                impact: r.score,
                description: `${r.severity} severity: ${r.description}`,
            }));

        // Calculate weighted scores (simplified - would use actual weights in production)
        const fingerprintScore = fingerprintFactors.reduce((sum, f) => sum + f.impact, 0);
        const behavioralScore = behavioralFactors.reduce((sum, f) => sum + f.impact, 0);
        const geographicScore = geographicFactors.reduce((sum, f) => sum + f.impact, 0);
        const reputationScore = reputationFactors.reduce((sum, f) => sum + f.impact, 0);

        // Identify risk and mitigating factors
        const riskFactors = result.reasons
            .filter(r => r.severity === 'high')
            .map(r => r.description);

        const mitigatingFactors = result.reasons
            .filter(r => r.severity === 'low')
            .map(r => `Low risk: ${r.description}`);

        // Determine recommended action
        let recommendedAction: DetailedDetectionReasoning['recommendedAction'] = 'ALLOW';
        if (result.suspicionScore >= 80) {
            recommendedAction = 'BAN';
        } else if (result.suspicionScore >= 70) {
            recommendedAction = 'BLOCK';
        } else if (result.suspicionScore >= 40) {
            recommendedAction = 'RATE_LIMIT';
        } else if (result.suspicionScore >= 20) {
            recommendedAction = 'MONITOR';
        }

        return {
            overallScore: result.suspicionScore,
            confidence: result.confidence,
            scoreBreakdown: {
                fingerprint: {
                    score: fingerprintScore,
                    weight: 0.3, // Default weight
                    factors: fingerprintFactors,
                },
                behavioral: {
                    score: behavioralScore,
                    weight: 0.3, // Default weight
                    factors: behavioralFactors,
                },
                geographic: {
                    score: geographicScore,
                    weight: 0.2, // Default weight
                    factors: geographicFactors,
                },
                reputation: {
                    score: reputationScore,
                    weight: 0.2, // Default weight
                    factors: reputationFactors,
                },
            },
            riskFactors,
            mitigatingFactors,
            recommendedAction,
        };
    }

    /**
     * Calculate SIEM-compatible severity level
     */
    private calculateSeverityLevel(suspicionScore: number): 'low' | 'medium' | 'high' | 'critical' {
        if (suspicionScore >= 80) return 'critical';
        if (suspicionScore >= 60) return 'high';
        if (suspicionScore >= 30) return 'medium';
        return 'low';
    }

    /**
     * Get configuration change history
     */
    getConfigurationHistory(): ConfigurationChangeEntry[] {
        return [...this.configurationHistory];
    }

    /**
     * Get false positive reports
     */
    getFalsePositiveReports(): FalsePositiveReport[] {
        return [...this.falsePositiveReports];
    }

    /**
     * Get enhanced analytics with false positive analysis
     */
    getEnhancedAnalytics(): DetectionAnalytics & {
        falsePositiveRate: number;
        configurationChanges: number;
        lastConfigurationChange?: number;
    } {
        const baseAnalytics = this.getAnalytics();
        const falsePositiveRate = baseAnalytics.totalRequests > 0
            ? baseAnalytics.falsePositives / baseAnalytics.totalRequests
            : 0;

        return {
            ...baseAnalytics,
            falsePositiveRate,
            configurationChanges: this.configurationHistory.length,
            lastConfigurationChange: this.configurationHistory.length > 0
                ? this.configurationHistory[this.configurationHistory.length - 1].timestamp
                : undefined,
        };
    }

    /**
     * Close logger and flush streams
     */
    close(): void {
        if (!isTest) {
            this.logPerformanceSummary();
        }

        this.logStream.end();
        this.metricsStream.end();
        this.auditLogStream.end();
    }

    /**
     * Write structured log entry
     */
    private writeLogEntry(entry: DetectionLogEntry): void {
        const logLine = JSON.stringify(entry) + '\n';
        this.logStream.write(logLine);

        // Also write to console in development
        if (process.env.NODE_ENV !== 'production' && !isTest) {
            const level = entry.level.toUpperCase();
            const message = `[${new Date(entry.timestamp).toISOString()}] [${level}] ${entry.event} - ${entry.ip} - ${entry.correlationId}`;
            console.log(message);
        }
    }

    /**
     * Write metrics entry
     */
    private writeMetricsEntry(entry: any): void {
        const metricsLine = JSON.stringify(entry) + '\n';
        this.metricsStream.write(metricsLine);
    }

    /**
     * Write audit entry
     */
    private writeAuditEntry(entry: any): void {
        const auditLine = JSON.stringify(entry) + '\n';
        this.auditLogStream.write(auditLine);

        // Also write to console in development for audit visibility
        if (process.env.NODE_ENV !== 'production' && !isTest) {
            console.log(`[AUDIT] ${entry.event} - ${entry.correlationId} - ${entry.changedBy || 'system'}`);
        }
    }

    /**
     * Initialize analytics structure
     */
    private initializeAnalytics(): DetectionAnalytics {
        return {
            totalRequests: 0,
            suspiciousRequests: 0,
            blockedRequests: 0,
            falsePositives: 0,
            detectionAccuracy: 0,
            averageProcessingTime: 0,
            topThreats: [],
            geoDistribution: {},
        };
    }

    /**
     * Update analytics with detection result
     */
    private updateAnalytics(result: DetectionResult, metrics: PerformanceMetrics, ip: string): void {
        if (result.isSuspicious) {
            this.analytics.suspiciousRequests++;
        }

        // Update average processing time
        const totalTime = this.analytics.averageProcessingTime * (this.analytics.totalRequests - 1);
        this.analytics.averageProcessingTime =
            (totalTime + metrics.totalProcessingTime) / this.analytics.totalRequests;

        // Update geo distribution
        if (result.metadata.geoData?.country) {
            const country = result.metadata.geoData.country;
            this.analytics.geoDistribution[country] = (this.analytics.geoDistribution[country] || 0) + 1;
        }

        // Calculate detection accuracy (simplified - would need ground truth data for real accuracy)
        this.analytics.detectionAccuracy = this.analytics.suspiciousRequests / this.analytics.totalRequests;
    }

    /**
     * Update threat summary for IP
     */
    private updateThreatSummary(ip: string, result: DetectionResult): void {
        const existing = this.threatSummaries.get(ip);

        if (existing) {
            existing.totalRequests++;
            existing.averageScore = (existing.averageScore * (existing.totalRequests - 1) + result.suspicionScore) / existing.totalRequests;
            existing.lastSeen = Date.now();

            // Update threat types
            const newThreats = result.reasons.map(r => r.category);
            existing.threatTypes = [...new Set([...existing.threatTypes, ...newThreats])];
        } else {
            this.threatSummaries.set(ip, {
                ip,
                country: result.metadata.geoData?.country || 'unknown',
                totalRequests: 1,
                averageScore: result.suspicionScore,
                lastSeen: Date.now(),
                threatTypes: result.reasons.map(r => r.category),
            });
        }
    }

    /**
     * Record performance metrics
     */
    private recordPerformanceMetrics(metrics: PerformanceMetrics): void {
        this.performanceBuffer.push(metrics);

        // Flush buffer if it gets too large
        if (this.performanceBuffer.length >= this.maxBufferSize) {
            this.logPerformanceSummary();
        }
    }

    /**
     * Calculate performance summary from buffer
     */
    private calculatePerformanceSummary() {
        const buffer = this.performanceBuffer;
        const count = buffer.length;

        return {
            averageProcessingTime: buffer.reduce((sum, m) => sum + m.totalProcessingTime, 0) / count,
            averageFingerprintingTime: buffer.reduce((sum, m) => sum + m.fingerprintingTime, 0) / count,
            averageBehaviorAnalysisTime: buffer.reduce((sum, m) => sum + m.behaviorAnalysisTime, 0) / count,
            averageGeoAnalysisTime: buffer.reduce((sum, m) => sum + m.geoAnalysisTime, 0) / count,
            averageScoringTime: buffer.reduce((sum, m) => sum + m.scoringTime, 0) / count,
            maxProcessingTime: Math.max(...buffer.map(m => m.totalProcessingTime)),
            minProcessingTime: Math.min(...buffer.map(m => m.totalProcessingTime)),
            averageMemoryUsage: {
                rss: buffer.reduce((sum, m) => sum + m.memoryUsage.rss, 0) / count,
                heapUsed: buffer.reduce((sum, m) => sum + m.memoryUsage.heapUsed, 0) / count,
                heapTotal: buffer.reduce((sum, m) => sum + m.memoryUsage.heapTotal, 0) / count,
                external: buffer.reduce((sum, m) => sum + m.memoryUsage.external, 0) / count,
            },
        };
    }

    /**
     * Sanitize headers for logging (remove sensitive information)
     */
    private sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
        const sanitized = { ...headers };

        // Remove sensitive headers
        const sensitiveHeaders = [
            'authorization',
            'cookie',
            'x-api-key',
            'x-auth-token',
            'x-access-token',
        ];

        sensitiveHeaders.forEach(header => {
            if (sanitized[header]) {
                sanitized[header] = '[REDACTED]';
            }
        });

        return sanitized;
    }

    /**
     * Log whitelist bypass for monitoring and analysis
     */
    logWhitelistBypass(
        context: CorrelationContext,
        whitelistResult: any, // WhitelistResult type from WhitelistManager
        req: any
    ): void {
        const entry: DetectionLogEntry = {
            correlationId: context.correlationId,
            requestId: context.requestId,
            timestamp: Date.now(),
            level: 'info',
            event: 'WHITELIST_BYPASS',
            ip: context.ip,
            userAgent: context.userAgent,
            path: req.path || req.url || 'unknown',
            method: req.method || 'unknown',
            metadata: {
                bypassType: whitelistResult.bypassType,
                reason: whitelistResult.reason,
                matchedEntries: whitelistResult.matchedEntries.length,
                matchedEntryIds: whitelistResult.matchedEntries.map((entry: any) => entry.id),
                // SIEM-compatible fields
                severity: 'info',
                category: 'security.whitelist',
                source: 'enhanced-bot-detection',
                version: '1.0.0',
            },
        };

        this.writeLogEntry(entry);
    }
}

// Singleton instance
let detectionLogger: DetectionLogger | null = null;

/**
 * Get singleton detection logger instance
 */
export function getDetectionLogger(): DetectionLogger {
    if (!detectionLogger) {
        detectionLogger = new DetectionLogger();
    }
    return detectionLogger;
}

/**
 * Create performance metrics object
 */
export function createPerformanceMetrics(
    totalTime: number,
    fingerprintingTime: number = 0,
    behaviorTime: number = 0,
    geoTime: number = 0,
    scoringTime: number = 0,
    startCpuUsage?: NodeJS.CpuUsage
): PerformanceMetrics {
    return {
        totalProcessingTime: totalTime,
        fingerprintingTime,
        behaviorAnalysisTime: behaviorTime,
        geoAnalysisTime: geoTime,
        scoringTime,
        memoryUsage: process.memoryUsage(),
        cpuUsage: startCpuUsage ? process.cpuUsage(startCpuUsage) : undefined,
    };
}