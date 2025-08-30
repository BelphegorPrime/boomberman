import { EventEmitter } from 'events';
import type { DetectionResult } from '../../detection/types/DetectionResult.js';
import type { DetectionAnalytics, ThreatSummary } from '../../detection/types/Analytics.js';
import type { PerformanceMetrics } from './detectionLogger.js';
import { isTest } from '../isTest.js';

/**
 * Real-time metrics for monitoring detection system performance
 */
export interface RealTimeMetrics {
    requestsPerSecond: number;
    averageResponseTime: number;
    suspiciousRequestRate: number;
    errorRate: number;
    memoryUsage: NodeJS.MemoryUsage;
    cpuUsage: number;
    activeConnections: number;
    cacheHitRate: number;
}

/**
 * Historical metrics for trend analysis
 */
export interface HistoricalMetrics {
    hourlyStats: HourlyStats[];
    dailyStats: DailyStats[];
    topThreats: ThreatSummary[];
    geoDistribution: Record<string, number>;
    detectionAccuracy: number;
    falsePositiveRate: number;
}

/**
 * Hourly aggregated statistics
 */
export interface HourlyStats {
    timestamp: number;
    totalRequests: number;
    suspiciousRequests: number;
    blockedRequests: number;
    averageProcessingTime: number;
    errorCount: number;
    uniqueIPs: number;
}

/**
 * Daily aggregated statistics
 */
export interface DailyStats {
    date: string;
    totalRequests: number;
    suspiciousRequests: number;
    blockedRequests: number;
    averageProcessingTime: number;
    errorCount: number;
    uniqueIPs: number;
    topCountries: Array<{ country: string; count: number }>;
}

/**
 * Metrics collector for gathering and aggregating detection system performance data
 */
export class MetricsCollector extends EventEmitter {
    private readonly windowSize = 60; // 60 seconds for real-time metrics
    private readonly maxHistorySize = 24 * 7; // 7 days of hourly data

    private requestCounts: number[] = [];
    private responseTimes: number[] = [];
    private suspiciousRequests: number[] = [];
    private errors: number[] = [];
    private uniqueIPs: Set<string> = new Set();

    private hourlyStats: HourlyStats[] = [];
    private dailyStats: DailyStats[] = [];
    private threatSummaries: Map<string, ThreatSummary> = new Map();
    private geoDistribution: Map<string, number> = new Map();

    private lastWindowReset = Date.now();
    private lastHourlyReset = Date.now();
    private lastDailyReset = Date.now();

    private totalRequests = 0;
    private totalSuspicious = 0;
    private totalBlocked = 0;
    private totalErrors = 0;
    private cacheHits = 0;
    private cacheMisses = 0;

    private intervals: NodeJS.Timeout[] = [];

    constructor() {
        super();
        this.setMaxListeners(20); // Increase limit for event listeners

        // Start periodic cleanup and aggregation only in non-test environments
        if (!isTest) {
            this.startPeriodicTasks();
        }
    }

    /**
     * Record a detection event
     */
    recordDetection(
        ip: string,
        result: DetectionResult,
        metrics: PerformanceMetrics,
        blocked: boolean = false
    ): void {
        const now = Date.now();

        // Update counters
        this.totalRequests++;
        this.requestCounts.push(now);
        this.responseTimes.push(metrics.totalProcessingTime);
        this.uniqueIPs.add(ip);

        if (result.isSuspicious) {
            this.totalSuspicious++;
            this.suspiciousRequests.push(now);
        }

        if (blocked) {
            this.totalBlocked++;
        }

        // Update geo distribution
        if (result.metadata.geoData?.country) {
            const country = result.metadata.geoData.country;
            this.geoDistribution.set(country, (this.geoDistribution.get(country) || 0) + 1);
        }

        // Update threat summary
        this.updateThreatSummary(ip, result);

        // Emit real-time event
        this.emit('detection', { ip, result, metrics, blocked });

        // Check if we need to reset windows
        this.checkWindowResets();
    }

    /**
     * Record an error event
     */
    recordError(error: Error, component?: string): void {
        const now = Date.now();
        this.totalErrors++;
        this.errors.push(now);

        this.emit('error', { error, component, timestamp: now });
    }

    /**
     * Record cache hit/miss
     */
    recordCacheEvent(hit: boolean): void {
        if (hit) {
            this.cacheHits++;
        } else {
            this.cacheMisses++;
        }
    }

    /**
     * Get real-time metrics
     */
    getRealTimeMetrics(): RealTimeMetrics {
        const now = Date.now();
        const windowStart = now - (this.windowSize * 1000);

        // Filter data to current window
        const recentRequests = this.requestCounts.filter(t => t >= windowStart);
        const recentResponses = this.responseTimes.slice(-recentRequests.length);
        const recentSuspicious = this.suspiciousRequests.filter(t => t >= windowStart);
        const recentErrors = this.errors.filter(t => t >= windowStart);

        return {
            requestsPerSecond: recentRequests.length / this.windowSize,
            averageResponseTime: recentResponses.length > 0
                ? recentResponses.reduce((sum, time) => sum + time, 0) / recentResponses.length
                : 0,
            suspiciousRequestRate: recentRequests.length > 0
                ? recentSuspicious.length / recentRequests.length
                : 0,
            errorRate: recentRequests.length > 0
                ? recentErrors.length / recentRequests.length
                : 0,
            memoryUsage: process.memoryUsage(),
            cpuUsage: this.getCpuUsage(),
            activeConnections: this.getActiveConnections(),
            cacheHitRate: this.cacheHits + this.cacheMisses > 0
                ? this.cacheHits / (this.cacheHits + this.cacheMisses)
                : 0,
        };
    }

    /**
     * Get historical metrics
     */
    getHistoricalMetrics(): HistoricalMetrics {
        return {
            hourlyStats: [...this.hourlyStats],
            dailyStats: [...this.dailyStats],
            topThreats: Array.from(this.threatSummaries.values())
                .sort((a, b) => b.averageScore - a.averageScore)
                .slice(0, 20),
            geoDistribution: Object.fromEntries(this.geoDistribution),
            detectionAccuracy: this.calculateDetectionAccuracy(),
            falsePositiveRate: this.calculateFalsePositiveRate(),
        };
    }

    /**
     * Get detection analytics with enhanced performance metrics
     */
    getDetectionAnalytics(): DetectionAnalytics {
        return {
            totalRequests: this.totalRequests,
            suspiciousRequests: this.totalSuspicious,
            blockedRequests: this.totalBlocked,
            falsePositives: Math.floor(this.totalSuspicious * this.calculateFalsePositiveRate()),
            detectionAccuracy: this.calculateDetectionAccuracy(),
            averageProcessingTime: this.responseTimes.length > 0
                ? this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length
                : 0,
            topThreats: Array.from(this.threatSummaries.values())
                .sort((a, b) => b.averageScore - a.averageScore)
                .slice(0, 10),
            geoDistribution: Object.fromEntries(this.geoDistribution),
        };
    }

    /**
     * Get comprehensive performance statistics
     */
    getPerformanceStatistics(): {
        responseTimePercentiles: {
            p50: number;
            p90: number;
            p95: number;
            p99: number;
        };
        throughputMetrics: {
            requestsPerSecond: number;
            peakRequestsPerSecond: number;
            averageRequestsPerMinute: number;
        };
        errorMetrics: {
            errorRate: number;
            errorCount: number;
            errorsByType: Record<string, number>;
        };
        resourceUsage: {
            averageMemoryUsage: number;
            peakMemoryUsage: number;
            averageCpuUsage: number;
        };
        cacheMetrics: {
            hitRate: number;
            totalHits: number;
            totalMisses: number;
        };
    } {
        const sortedResponseTimes = [...this.responseTimes].sort((a, b) => a - b);
        const now = Date.now();
        const windowStart = now - (this.windowSize * 1000);
        const recentRequests = this.requestCounts.filter(t => t >= windowStart);

        return {
            responseTimePercentiles: {
                p50: this.calculatePercentile(sortedResponseTimes, 0.5),
                p90: this.calculatePercentile(sortedResponseTimes, 0.9),
                p95: this.calculatePercentile(sortedResponseTimes, 0.95),
                p99: this.calculatePercentile(sortedResponseTimes, 0.99),
            },
            throughputMetrics: {
                requestsPerSecond: recentRequests.length / this.windowSize,
                peakRequestsPerSecond: this.calculatePeakThroughput(),
                averageRequestsPerMinute: this.totalRequests / Math.max(1, (now - this.lastWindowReset) / 60000),
            },
            errorMetrics: {
                errorRate: this.totalRequests > 0 ? this.totalErrors / this.totalRequests : 0,
                errorCount: this.totalErrors,
                errorsByType: {}, // Would be populated with actual error categorization
            },
            resourceUsage: {
                averageMemoryUsage: this.calculateAverageMemoryUsage(),
                peakMemoryUsage: this.calculatePeakMemoryUsage(),
                averageCpuUsage: this.getCpuUsage(),
            },
            cacheMetrics: {
                hitRate: this.cacheHits + this.cacheMisses > 0
                    ? this.cacheHits / (this.cacheHits + this.cacheMisses)
                    : 0,
                totalHits: this.cacheHits,
                totalMisses: this.cacheMisses,
            },
        };
    }

    /**
     * Reset all metrics (useful for testing)
     */
    reset(): void {
        this.requestCounts = [];
        this.responseTimes = [];
        this.suspiciousRequests = [];
        this.errors = [];
        this.uniqueIPs.clear();
        this.hourlyStats = [];
        this.dailyStats = [];
        this.threatSummaries.clear();
        this.geoDistribution.clear();

        this.totalRequests = 0;
        this.totalSuspicious = 0;
        this.totalBlocked = 0;
        this.totalErrors = 0;
        this.cacheHits = 0;
        this.cacheMisses = 0;

        this.lastWindowReset = Date.now();
        this.lastHourlyReset = Date.now();
        this.lastDailyReset = Date.now();

        // Stop and clear intervals
        this.stopPeriodicTasks();
    }

    /**
     * Start periodic tasks for cleanup and aggregation
     */
    private startPeriodicTasks(): void {
        // Clean up old data every minute
        this.intervals.push(setInterval(() => {
            this.cleanupOldData();
        }, 60 * 1000));

        // Aggregate hourly stats every hour
        this.intervals.push(setInterval(() => {
            this.aggregateHourlyStats();
        }, 60 * 60 * 1000));

        // Aggregate daily stats every day
        this.intervals.push(setInterval(() => {
            this.aggregateDailyStats();
        }, 24 * 60 * 60 * 1000));

        // Emit metrics update every 10 seconds
        this.intervals.push(setInterval(() => {
            this.emit('metricsUpdate', this.getRealTimeMetrics());
        }, 10 * 1000));
    }

    /**
     * Stop periodic tasks and clean up intervals
     */
    public stopPeriodicTasks(): void {
        this.intervals.forEach(interval => clearInterval(interval));
        this.intervals = [];
    }

    /**
     * Clean up old data to prevent memory leaks
     */
    private cleanupOldData(): void {
        const now = Date.now();
        const cutoff = now - (this.windowSize * 2 * 1000); // Keep 2x window size

        this.requestCounts = this.requestCounts.filter(t => t >= cutoff);
        this.suspiciousRequests = this.suspiciousRequests.filter(t => t >= cutoff);
        this.errors = this.errors.filter(t => t >= cutoff);

        // Keep response times in sync with request counts
        const keepCount = this.requestCounts.length;
        if (this.responseTimes.length > keepCount) {
            this.responseTimes = this.responseTimes.slice(-keepCount);
        }

        // Clean up old hourly stats
        if (this.hourlyStats.length > this.maxHistorySize) {
            this.hourlyStats = this.hourlyStats.slice(-this.maxHistorySize);
        }

        // Clean up old daily stats (keep 30 days)
        if (this.dailyStats.length > 30) {
            this.dailyStats = this.dailyStats.slice(-30);
        }
    }

    /**
     * Check if windows need to be reset
     */
    private checkWindowResets(): void {
        const now = Date.now();

        // Reset hourly window
        if (now - this.lastHourlyReset >= 60 * 60 * 1000) {
            this.aggregateHourlyStats();
            this.lastHourlyReset = now;
        }

        // Reset daily window
        if (now - this.lastDailyReset >= 24 * 60 * 60 * 1000) {
            this.aggregateDailyStats();
            this.lastDailyReset = now;
        }
    }

    /**
     * Aggregate hourly statistics
     */
    private aggregateHourlyStats(): void {
        const now = Date.now();
        const hourStart = now - (60 * 60 * 1000);

        const hourlyRequests = this.requestCounts.filter(t => t >= hourStart);
        const hourlySuspicious = this.suspiciousRequests.filter(t => t >= hourStart);
        const hourlyErrors = this.errors.filter(t => t >= hourStart);
        const hourlyResponses = this.responseTimes.slice(-hourlyRequests.length);

        const stats: HourlyStats = {
            timestamp: Math.floor(now / (60 * 60 * 1000)) * (60 * 60 * 1000),
            totalRequests: hourlyRequests.length,
            suspiciousRequests: hourlySuspicious.length,
            blockedRequests: Math.floor(hourlySuspicious.length * 0.3), // Estimate
            averageProcessingTime: hourlyResponses.length > 0
                ? hourlyResponses.reduce((sum, time) => sum + time, 0) / hourlyResponses.length
                : 0,
            errorCount: hourlyErrors.length,
            uniqueIPs: this.uniqueIPs.size,
        };

        this.hourlyStats.push(stats);
        this.emit('hourlyStats', stats);
    }

    /**
     * Aggregate daily statistics
     */
    private aggregateDailyStats(): void {
        const now = new Date();
        const today = now.toISOString().split('T')[0];

        const dayStart = new Date(today).getTime();
        const dayEnd = dayStart + (24 * 60 * 60 * 1000);

        const dailyRequests = this.requestCounts.filter(t => t >= dayStart && t < dayEnd);
        const dailySuspicious = this.suspiciousRequests.filter(t => t >= dayStart && t < dayEnd);
        const dailyErrors = this.errors.filter(t => t >= dayStart && t < dayEnd);
        const dailyResponses = this.responseTimes.slice(-dailyRequests.length);

        // Get top countries for the day
        const topCountries = Array.from(this.geoDistribution.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([country, count]) => ({ country, count }));

        const stats: DailyStats = {
            date: today,
            totalRequests: dailyRequests.length,
            suspiciousRequests: dailySuspicious.length,
            blockedRequests: Math.floor(dailySuspicious.length * 0.3), // Estimate
            averageProcessingTime: dailyResponses.length > 0
                ? dailyResponses.reduce((sum, time) => sum + time, 0) / dailyResponses.length
                : 0,
            errorCount: dailyErrors.length,
            uniqueIPs: this.uniqueIPs.size,
            topCountries,
        };

        this.dailyStats.push(stats);
        this.emit('dailyStats', stats);

        // Reset daily counters
        this.uniqueIPs.clear();
    }

    /**
     * Update threat summary for an IP
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
     * Calculate detection accuracy (simplified - would need ground truth data)
     */
    private calculateDetectionAccuracy(): number {
        if (this.totalRequests === 0) return 0;

        // Simplified accuracy calculation
        // In reality, this would require labeled data for true positives/negatives
        const estimatedAccuracy = Math.max(0.85, 1 - (this.totalErrors / this.totalRequests));
        return Math.min(1, estimatedAccuracy);
    }

    /**
     * Calculate false positive rate (estimated)
     */
    private calculateFalsePositiveRate(): number {
        if (this.totalSuspicious === 0) return 0;

        // Estimated false positive rate based on system performance
        // This would be calibrated based on actual feedback
        return Math.min(0.05, this.totalErrors / Math.max(1, this.totalSuspicious));
    }

    /**
     * Get CPU usage percentage
     */
    private getCpuUsage(): number {
        // This is a simplified CPU usage calculation
        // In production, you might want to use a more sophisticated method
        const usage = process.cpuUsage();
        return (usage.user + usage.system) / 1000000; // Convert to seconds
    }

    /**
     * Get active connections count
     */
    private getActiveConnections(): number {
        // This would typically be provided by the HTTP server
        // For now, return an estimate based on recent requests
        const now = Date.now();
        const recentWindow = 10 * 1000; // 10 seconds
        const recentRequests = this.requestCounts.filter(t => t >= now - recentWindow);
        return recentRequests.length;
    }

    /**
     * Calculate percentile for response times
     */
    private calculatePercentile(sortedArray: number[], percentile: number): number {
        if (sortedArray.length === 0) return 0;

        const index = Math.ceil(sortedArray.length * percentile) - 1;
        return sortedArray[Math.max(0, index)];
    }

    /**
     * Calculate peak throughput (requests per second)
     */
    private calculatePeakThroughput(): number {
        if (this.requestCounts.length === 0) return 0;

        const now = Date.now();
        let maxThroughput = 0;

        // Check throughput for each second in the last minute
        for (let i = 0; i < 60; i++) {
            const windowEnd = now - (i * 1000);
            const windowStart = windowEnd - 1000;
            const requestsInWindow = this.requestCounts.filter(t => t >= windowStart && t < windowEnd);
            maxThroughput = Math.max(maxThroughput, requestsInWindow.length);
        }

        // If no historical data, return current window throughput
        if (maxThroughput === 0 && this.requestCounts.length > 0) {
            const windowStart = now - (this.windowSize * 1000);
            const recentRequests = this.requestCounts.filter(t => t >= windowStart);
            return recentRequests.length / this.windowSize;
        }

        return maxThroughput;
    }

    /**
     * Calculate average memory usage
     */
    private calculateAverageMemoryUsage(): number {
        // This would be calculated from stored memory usage samples
        // For now, return current memory usage
        const memUsage = process.memoryUsage();
        return memUsage.heapUsed;
    }

    /**
     * Calculate peak memory usage
     */
    private calculatePeakMemoryUsage(): number {
        // This would be calculated from stored memory usage samples
        // For now, return current memory usage
        const memUsage = process.memoryUsage();
        return memUsage.heapTotal;
    }
}

// Singleton instance
let metricsCollector: MetricsCollector | null = null;

/**
 * Get singleton metrics collector instance
 */
export function getMetricsCollector(): MetricsCollector {
    if (!metricsCollector) {
        metricsCollector = new MetricsCollector();
    }
    return metricsCollector;
}