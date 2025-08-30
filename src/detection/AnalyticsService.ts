import { EventEmitter } from 'events';
import type { DetectionAnalytics, ThreatSummary } from './types/Analytics.js';
import type { DetectionResult } from './types/DetectionResult.js';
import type { GeoLocation } from './types/GeoLocation.js';
import { getMetricsCollector, type HistoricalMetrics, type RealTimeMetrics } from '../utils/logger/metricsCollector.js';

/**
 * Time range options for analytics reports
 */
export type TimeRange = 'hour' | 'day' | 'week' | 'month';

/**
 * Analytics report configuration
 */
export interface AnalyticsReportConfig {
    timeRange: TimeRange;
    includeGeoDistribution: boolean;
    includeThreatSummary: boolean;
    includePerformanceMetrics: boolean;
    maxThreats: number;
    maxCountries: number;
}

/**
 * Comprehensive analytics report
 */
export interface AnalyticsReport {
    metadata: {
        generatedAt: number;
        timeRange: TimeRange;
        startTime: number;
        endTime: number;
    };
    summary: {
        totalRequests: number;
        suspiciousRequests: number;
        blockedRequests: number;
        detectionAccuracy: number;
        falsePositiveRate: number;
        averageProcessingTime: number;
    };
    threats: ThreatSummary[];
    geoDistribution: GeographicDistribution;
    performanceMetrics: PerformanceReport;
    trends: TrendAnalysis;
}

/**
 * Geographic distribution analysis
 */
export interface GeographicDistribution {
    byCountry: Array<{ country: string; requests: number; percentage: number }>;
    byRiskLevel: {
        low: number;
        medium: number;
        high: number;
    };
    vpnTraffic: number;
    proxyTraffic: number;
    hostingProviderTraffic: number;
    torTraffic: number;
}

/**
 * Performance analysis report
 */
export interface PerformanceReport {
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
    resourceUtilization: {
        averageMemoryUsage: number;
        peakMemoryUsage: number;
        averageCpuUsage: number;
        cacheHitRate: number;
    };
    errorMetrics: {
        errorRate: number;
        errorCount: number;
        errorsByComponent: Record<string, number>;
    };
}

/**
 * Trend analysis data
 */
export interface TrendAnalysis {
    requestTrend: Array<{ timestamp: number; count: number }>;
    suspiciousTrend: Array<{ timestamp: number; count: number }>;
    performanceTrend: Array<{ timestamp: number; averageTime: number }>;
    topGrowingThreats: Array<{ ip: string; growthRate: number; currentScore: number }>;
}

/**
 * Threat intelligence data
 */
export interface ThreatIntelligence {
    emergingThreats: ThreatSummary[];
    repeatOffenders: ThreatSummary[];
    geographicHotspots: Array<{ country: string; riskScore: number; requestCount: number }>;
    attackPatterns: Array<{ pattern: string; frequency: number; severity: 'low' | 'medium' | 'high' }>;
}

/**
 * Analytics service for generating comprehensive reports and insights
 */
export class AnalyticsService extends EventEmitter {
    private readonly metricsCollector = getMetricsCollector();
    private readonly reportCache = new Map<string, { report: AnalyticsReport; timestamp: number }>();
    private readonly cacheTimeout = 5 * 60 * 1000; // 5 minutes

    constructor() {
        super();
        this.setMaxListeners(20); // Increase limit for event listeners
        this.setupEventListeners();
    }

    /**
     * Generate a comprehensive analytics report
     */
    async generateReport(config: AnalyticsReportConfig): Promise<AnalyticsReport> {
        const cacheKey = this.getCacheKey(config);
        const cached = this.reportCache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.report;
        }

        const report = await this.buildReport(config);
        this.reportCache.set(cacheKey, { report, timestamp: Date.now() });

        this.emit('reportGenerated', { config, report });
        return report;
    }

    /**
     * Get real-time analytics dashboard data
     */
    getRealTimeDashboard(): {
        realTimeMetrics: RealTimeMetrics;
        detectionAnalytics: DetectionAnalytics;
        recentThreats: ThreatSummary[];
        alertsCount: number;
    } {
        const realTimeMetrics = this.metricsCollector.getRealTimeMetrics();
        const detectionAnalytics = this.metricsCollector.getDetectionAnalytics();
        const recentThreats = detectionAnalytics.topThreats.slice(0, 5);
        const alertsCount = this.calculateActiveAlerts(detectionAnalytics);

        return {
            realTimeMetrics,
            detectionAnalytics,
            recentThreats,
            alertsCount,
        };
    }

    /**
     * Generate threat intelligence report
     */
    generateThreatIntelligence(): ThreatIntelligence {
        const analytics = this.metricsCollector.getDetectionAnalytics();
        const historical = this.metricsCollector.getHistoricalMetrics();

        return {
            emergingThreats: this.identifyEmergingThreats(analytics.topThreats),
            repeatOffenders: this.identifyRepeatOffenders(analytics.topThreats),
            geographicHotspots: this.identifyGeographicHotspots(analytics.geoDistribution),
            attackPatterns: this.identifyAttackPatterns(analytics.topThreats),
        };
    }

    /**
     * Get geographic distribution analysis
     */
    getGeographicDistribution(): GeographicDistribution {
        const analytics = this.metricsCollector.getDetectionAnalytics();
        const totalRequests = analytics.totalRequests;

        const byCountry = Object.entries(analytics.geoDistribution)
            .map(([country, requests]) => ({
                country,
                requests,
                percentage: totalRequests > 0 ? (requests / totalRequests) * 100 : 0,
            }))
            .sort((a, b) => b.requests - a.requests);

        // Analyze risk levels based on threat data
        const riskAnalysis = this.analyzeGeographicRisk(analytics.topThreats);

        return {
            byCountry,
            byRiskLevel: riskAnalysis.byRiskLevel,
            vpnTraffic: riskAnalysis.vpnTraffic,
            proxyTraffic: riskAnalysis.proxyTraffic,
            hostingProviderTraffic: riskAnalysis.hostingProviderTraffic,
            torTraffic: riskAnalysis.torTraffic,
        };
    }

    /**
     * Get performance analysis
     */
    getPerformanceAnalysis(): PerformanceReport {
        const perfStats = this.metricsCollector.getPerformanceStatistics();

        return {
            responseTimePercentiles: perfStats.responseTimePercentiles,
            throughputMetrics: perfStats.throughputMetrics,
            resourceUtilization: {
                averageMemoryUsage: perfStats.resourceUsage.averageMemoryUsage,
                peakMemoryUsage: perfStats.resourceUsage.peakMemoryUsage,
                averageCpuUsage: perfStats.resourceUsage.averageCpuUsage,
                cacheHitRate: perfStats.cacheMetrics.hitRate,
            },
            errorMetrics: {
                errorRate: perfStats.errorMetrics.errorRate,
                errorCount: perfStats.errorMetrics.errorCount,
                errorsByComponent: perfStats.errorMetrics.errorsByType,
            },
        };
    }

    /**
     * Generate trend analysis
     */
    generateTrendAnalysis(timeRange: TimeRange): TrendAnalysis {
        const historical = this.metricsCollector.getHistoricalMetrics();
        const analytics = this.metricsCollector.getDetectionAnalytics();

        const timeWindow = this.getTimeWindow(timeRange);
        const filteredStats = historical.hourlyStats.filter(
            stat => stat.timestamp >= timeWindow.start
        );

        return {
            requestTrend: filteredStats.map(stat => ({
                timestamp: stat.timestamp,
                count: stat.totalRequests,
            })),
            suspiciousTrend: filteredStats.map(stat => ({
                timestamp: stat.timestamp,
                count: stat.suspiciousRequests,
            })),
            performanceTrend: filteredStats.map(stat => ({
                timestamp: stat.timestamp,
                averageTime: stat.averageProcessingTime,
            })),
            topGrowingThreats: this.identifyGrowingThreats(analytics.topThreats),
        };
    }

    /**
     * Export analytics data in various formats
     */
    exportData(format: 'json' | 'csv', config: AnalyticsReportConfig): string {
        const analytics = this.metricsCollector.getDetectionAnalytics();

        switch (format) {
            case 'json':
                return JSON.stringify(analytics, null, 2);
            case 'csv':
                return this.convertToCSV(analytics);
            default:
                throw new Error(`Unsupported export format: ${format}`);
        }
    }

    /**
     * Clear analytics cache
     */
    clearCache(): void {
        this.reportCache.clear();
        this.emit('cacheCleared');
    }

    /**
     * Get analytics summary for a specific IP
     */
    getIPAnalytics(ip: string): {
        threat: ThreatSummary | null;
        riskAssessment: {
            riskLevel: 'low' | 'medium' | 'high';
            riskFactors: string[];
            recommendations: string[];
        };
        historicalActivity: Array<{
            timestamp: number;
            suspicionScore: number;
            action: 'allowed' | 'rate_limited' | 'blocked';
        }>;
    } {
        const analytics = this.metricsCollector.getDetectionAnalytics();
        const threat = analytics.topThreats.find(t => t.ip === ip) || null;

        const riskAssessment = this.assessIPRisk(threat);
        const historicalActivity = this.getIPHistory(ip);

        return {
            threat,
            riskAssessment,
            historicalActivity,
        };
    }

    /**
     * Setup event listeners for metrics collector
     */
    private setupEventListeners(): void {
        this.metricsCollector.on('detection', (event) => {
            this.emit('detectionEvent', event);
        });

        this.metricsCollector.on('error', (event) => {
            this.emit('errorEvent', event);
        });

        this.metricsCollector.on('metricsUpdate', (metrics) => {
            this.emit('metricsUpdate', metrics);
        });
    }

    /**
     * Build comprehensive analytics report
     */
    private async buildReport(config: AnalyticsReportConfig): Promise<AnalyticsReport> {
        const timeWindow = this.getTimeWindow(config.timeRange);
        const analytics = this.metricsCollector.getDetectionAnalytics();
        const historical = this.metricsCollector.getHistoricalMetrics();

        const report: AnalyticsReport = {
            metadata: {
                generatedAt: Date.now(),
                timeRange: config.timeRange,
                startTime: timeWindow.start,
                endTime: timeWindow.end,
            },
            summary: {
                totalRequests: analytics.totalRequests,
                suspiciousRequests: analytics.suspiciousRequests,
                blockedRequests: analytics.blockedRequests,
                detectionAccuracy: analytics.detectionAccuracy,
                falsePositiveRate: analytics.falsePositives / Math.max(1, analytics.suspiciousRequests),
                averageProcessingTime: analytics.averageProcessingTime,
            },
            threats: config.includeThreatSummary
                ? analytics.topThreats.slice(0, config.maxThreats)
                : [],
            geoDistribution: config.includeGeoDistribution
                ? this.getGeographicDistribution()
                : this.getEmptyGeoDistribution(),
            performanceMetrics: config.includePerformanceMetrics
                ? this.getPerformanceAnalysis()
                : this.getEmptyPerformanceReport(),
            trends: this.generateTrendAnalysis(config.timeRange),
        };

        return report;
    }

    /**
     * Get cache key for report configuration
     */
    private getCacheKey(config: AnalyticsReportConfig): string {
        return JSON.stringify(config);
    }

    /**
     * Get time window for analysis
     */
    private getTimeWindow(timeRange: TimeRange): { start: number; end: number } {
        const now = Date.now();
        let start: number;

        switch (timeRange) {
            case 'hour':
                start = now - (60 * 60 * 1000);
                break;
            case 'day':
                start = now - (24 * 60 * 60 * 1000);
                break;
            case 'week':
                start = now - (7 * 24 * 60 * 60 * 1000);
                break;
            case 'month':
                start = now - (30 * 24 * 60 * 60 * 1000);
                break;
            default:
                start = now - (24 * 60 * 60 * 1000);
        }

        return { start, end: now };
    }

    /**
     * Calculate active alerts count
     */
    private calculateActiveAlerts(analytics: DetectionAnalytics): number {
        const highRiskThreats = analytics.topThreats.filter(t => t.averageScore > 70);
        const recentThreats = analytics.topThreats.filter(
            t => Date.now() - t.lastSeen < 60 * 60 * 1000 // Last hour
        );

        return highRiskThreats.length + recentThreats.length;
    }

    /**
     * Identify emerging threats
     */
    private identifyEmergingThreats(threats: ThreatSummary[]): ThreatSummary[] {
        const recentThreshold = Date.now() - (24 * 60 * 60 * 1000); // Last 24 hours
        return threats
            .filter(t => t.lastSeen > recentThreshold && t.averageScore > 50)
            .sort((a, b) => b.lastSeen - a.lastSeen)
            .slice(0, 10);
    }

    /**
     * Identify repeat offenders
     */
    private identifyRepeatOffenders(threats: ThreatSummary[]): ThreatSummary[] {
        return threats
            .filter(t => t.totalRequests > 10 && t.averageScore > 40)
            .sort((a, b) => b.totalRequests - a.totalRequests)
            .slice(0, 10);
    }

    /**
     * Identify geographic hotspots
     */
    private identifyGeographicHotspots(geoDistribution: Record<string, number>): Array<{
        country: string;
        riskScore: number;
        requestCount: number;
    }> {
        return Object.entries(geoDistribution)
            .map(([country, count]) => ({
                country,
                riskScore: this.calculateCountryRiskScore(country, count),
                requestCount: count,
            }))
            .filter(hotspot => hotspot.riskScore > 30)
            .sort((a, b) => b.riskScore - a.riskScore)
            .slice(0, 10);
    }

    /**
     * Identify attack patterns
     */
    private identifyAttackPatterns(threats: ThreatSummary[]): Array<{
        pattern: string;
        frequency: number;
        severity: 'low' | 'medium' | 'high';
    }> {
        const patterns = new Map<string, { count: number; totalScore: number }>();

        threats.forEach(threat => {
            threat.threatTypes.forEach(type => {
                const existing = patterns.get(type) || { count: 0, totalScore: 0 };
                patterns.set(type, {
                    count: existing.count + 1,
                    totalScore: existing.totalScore + threat.averageScore,
                });
            });
        });

        return Array.from(patterns.entries())
            .map(([pattern, data]) => ({
                pattern,
                frequency: data.count,
                severity: this.calculatePatternSeverity(data.totalScore / data.count),
            }))
            .sort((a, b) => b.frequency - a.frequency);
    }

    /**
     * Analyze geographic risk
     */
    private analyzeGeographicRisk(threats: ThreatSummary[]): {
        byRiskLevel: { low: number; medium: number; high: number };
        vpnTraffic: number;
        proxyTraffic: number;
        hostingProviderTraffic: number;
        torTraffic: number;
    } {
        const riskLevels = { low: 0, medium: 0, high: 0 };
        let vpnTraffic = 0;
        let proxyTraffic = 0;
        let hostingProviderTraffic = 0;
        let torTraffic = 0;

        threats.forEach(threat => {
            // Categorize by risk level
            if (threat.averageScore < 30) {
                riskLevels.low += threat.totalRequests;
            } else if (threat.averageScore < 70) {
                riskLevels.medium += threat.totalRequests;
            } else {
                riskLevels.high += threat.totalRequests;
            }

            // Count special traffic types (would need geo data integration)
            // This is simplified - in reality, you'd check the actual geo data
            if (threat.threatTypes.includes('geographic')) {
                if (threat.averageScore > 60) {
                    vpnTraffic += threat.totalRequests * 0.3; // Estimate
                    proxyTraffic += threat.totalRequests * 0.2;
                    hostingProviderTraffic += threat.totalRequests * 0.4;
                    torTraffic += threat.totalRequests * 0.1;
                }
            }
        });

        return {
            byRiskLevel: riskLevels,
            vpnTraffic: Math.floor(vpnTraffic),
            proxyTraffic: Math.floor(proxyTraffic),
            hostingProviderTraffic: Math.floor(hostingProviderTraffic),
            torTraffic: Math.floor(torTraffic),
        };
    }

    /**
     * Identify growing threats
     */
    private identifyGrowingThreats(threats: ThreatSummary[]): Array<{
        ip: string;
        growthRate: number;
        currentScore: number;
    }> {
        // This is simplified - in reality, you'd track historical data
        return threats
            .filter(t => t.totalRequests > 5)
            .map(threat => ({
                ip: threat.ip,
                growthRate: this.calculateGrowthRate(threat),
                currentScore: threat.averageScore,
            }))
            .filter(t => t.growthRate > 1.5)
            .sort((a, b) => b.growthRate - a.growthRate)
            .slice(0, 10);
    }

    /**
     * Convert analytics to CSV format
     */
    private convertToCSV(analytics: DetectionAnalytics): string {
        const headers = [
            'IP',
            'Country',
            'Total Requests',
            'Average Score',
            'Last Seen',
            'Threat Types',
        ];

        const rows = analytics.topThreats.map(threat => [
            threat.ip,
            threat.country,
            threat.totalRequests.toString(),
            threat.averageScore.toFixed(2),
            new Date(threat.lastSeen).toISOString(),
            threat.threatTypes.join(';'),
        ]);

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }

    /**
     * Assess IP risk level
     */
    private assessIPRisk(threat: ThreatSummary | null): {
        riskLevel: 'low' | 'medium' | 'high';
        riskFactors: string[];
        recommendations: string[];
    } {
        if (!threat) {
            return {
                riskLevel: 'low',
                riskFactors: ['No suspicious activity detected'],
                recommendations: ['Continue monitoring'],
            };
        }

        const riskFactors: string[] = [];
        const recommendations: string[] = [];

        if (threat.averageScore > 70) {
            riskFactors.push('High suspicion score');
            recommendations.push('Consider blocking this IP');
        }

        if (threat.totalRequests > 100) {
            riskFactors.push('High request volume');
            recommendations.push('Apply rate limiting');
        }

        if (threat.threatTypes.includes('fingerprint')) {
            riskFactors.push('Bot-like fingerprint detected');
            recommendations.push('Implement CAPTCHA challenges');
        }

        const riskLevel = threat.averageScore > 70 ? 'high' :
            threat.averageScore > 30 ? 'medium' : 'low';

        return { riskLevel, riskFactors, recommendations };
    }

    /**
     * Get IP historical activity (simplified)
     */
    private getIPHistory(ip: string): Array<{
        timestamp: number;
        suspicionScore: number;
        action: 'allowed' | 'rate_limited' | 'blocked';
    }> {
        // This would be implemented with actual historical data storage
        // For now, return empty array
        return [];
    }

    /**
     * Calculate country risk score
     */
    private calculateCountryRiskScore(country: string, requestCount: number): number {
        // Simplified risk calculation based on country and request volume
        const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
        const mediumRiskCountries = ['BR', 'IN', 'PK', 'BD'];

        let baseScore = 10;

        if (highRiskCountries.includes(country)) {
            baseScore = 60;
        } else if (mediumRiskCountries.includes(country)) {
            baseScore = 30;
        }

        // Adjust based on request volume - lower threshold for testing
        const volumeMultiplier = Math.min(2, requestCount / 10);
        return Math.min(100, baseScore * volumeMultiplier);
    }

    /**
     * Calculate pattern severity
     */
    private calculatePatternSeverity(averageScore: number): 'low' | 'medium' | 'high' {
        if (averageScore > 70) return 'high';
        if (averageScore > 30) return 'medium';
        return 'low';
    }

    /**
     * Calculate growth rate for threat
     */
    private calculateGrowthRate(threat: ThreatSummary): number {
        // Simplified growth rate calculation
        // In reality, this would compare current activity to historical baseline
        const recentActivity = Date.now() - threat.lastSeen < 60 * 60 * 1000 ? 1 : 0;
        const requestRate = threat.totalRequests / Math.max(1, (Date.now() - threat.lastSeen) / (60 * 60 * 1000));
        return requestRate * (1 + recentActivity);
    }

    /**
     * Get empty geographic distribution
     */
    private getEmptyGeoDistribution(): GeographicDistribution {
        return {
            byCountry: [],
            byRiskLevel: { low: 0, medium: 0, high: 0 },
            vpnTraffic: 0,
            proxyTraffic: 0,
            hostingProviderTraffic: 0,
            torTraffic: 0,
        };
    }

    /**
     * Get empty performance report
     */
    private getEmptyPerformanceReport(): PerformanceReport {
        return {
            responseTimePercentiles: { p50: 0, p90: 0, p95: 0, p99: 0 },
            throughputMetrics: { requestsPerSecond: 0, peakRequestsPerSecond: 0, averageRequestsPerMinute: 0 },
            resourceUtilization: { averageMemoryUsage: 0, peakMemoryUsage: 0, averageCpuUsage: 0, cacheHitRate: 0 },
            errorMetrics: { errorRate: 0, errorCount: 0, errorsByComponent: {} },
        };
    }
}

// Singleton instance
let analyticsService: AnalyticsService | null = null;

/**
 * Get singleton analytics service instance
 */
export function getAnalyticsService(): AnalyticsService {
    if (!analyticsService) {
        analyticsService = new AnalyticsService();
    }
    return analyticsService;
}