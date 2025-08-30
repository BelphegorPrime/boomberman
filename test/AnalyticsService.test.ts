import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import {
    AnalyticsService,
    getAnalyticsService,
    type AnalyticsReportConfig,
    type AnalyticsReport,
    type GeographicDistribution,
    type PerformanceReport,
    type TrendAnalysis,
    type ThreatIntelligence,
} from '../src/detection/AnalyticsService.js';
import { getMetricsCollector, MetricsCollector } from '../src/utils/logger/metricsCollector.js';
import type { DetectionResult } from '../src/detection/types/DetectionResult.js';
import type { PerformanceMetrics } from '../src/utils/logger/detectionLogger.js';

describe('AnalyticsService', () => {
    let analyticsService: AnalyticsService;
    let metricsCollector: MetricsCollector;

    beforeEach(() => {
        // Reset metrics collector
        metricsCollector = getMetricsCollector();
        metricsCollector.reset();

        analyticsService = new AnalyticsService();
    });

    afterEach(() => {
        analyticsService.removeAllListeners();
        analyticsService.clearCache();
        metricsCollector.stopPeriodicTasks();
    });

    describe('generateReport', () => {
        test('should generate comprehensive analytics report', async () => {
            // Setup test data
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [
                    {
                        category: 'fingerprint',
                        severity: 'high',
                        description: 'Bot detected',
                        score: 75,
                    },
                ],
                fingerprint: 'bot-fingerprint',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                    geoData: {
                        country: 'CN',
                        region: 'Beijing',
                        city: 'Beijing',
                        isVPN: true,
                        isProxy: false,
                        isHosting: false,
                        isTor: false,
                        riskScore: 40,
                        asn: 54321,
                        organization: 'VPN Provider',
                    },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('10.0.0.1', result, metrics, true);

            const config: AnalyticsReportConfig = {
                timeRange: 'day',
                includeGeoDistribution: true,
                includeThreatSummary: true,
                includePerformanceMetrics: true,
                maxThreats: 10,
                maxCountries: 10,
            };

            const report = await analyticsService.generateReport(config);

            expect(report).toMatchObject({
                metadata: {
                    generatedAt: expect.any(Number),
                    timeRange: 'day',
                    startTime: expect.any(Number),
                    endTime: expect.any(Number),
                },
                summary: {
                    totalRequests: 1,
                    suspiciousRequests: 1,
                    blockedRequests: 1,
                    detectionAccuracy: expect.any(Number),
                    falsePositiveRate: expect.any(Number),
                    averageProcessingTime: 30.0,
                },
                threats: expect.any(Array),
                geoDistribution: expect.any(Object),
                performanceMetrics: expect.any(Object),
                trends: expect.any(Object),
            });

            expect(report.threats).toHaveLength(1);
            expect(report.threats[0].ip).toBe('10.0.0.1');
            expect(report.geoDistribution.byCountry).toContainEqual({
                country: 'CN',
                requests: 1,
                percentage: 100,
            });
        });

        test('should cache reports and return cached version', async () => {
            const config: AnalyticsReportConfig = {
                timeRange: 'hour',
                includeGeoDistribution: false,
                includeThreatSummary: false,
                includePerformanceMetrics: false,
                maxThreats: 5,
                maxCountries: 5,
            };

            const report1 = await analyticsService.generateReport(config);
            const report2 = await analyticsService.generateReport(config);

            expect(report1).toBe(report2); // Should be same object reference due to caching
        });

        test('should handle different time ranges', async () => {
            const timeRanges: Array<'hour' | 'day' | 'week' | 'month'> = ['hour', 'day', 'week', 'month'];

            for (const timeRange of timeRanges) {
                const config: AnalyticsReportConfig = {
                    timeRange,
                    includeGeoDistribution: false,
                    includeThreatSummary: false,
                    includePerformanceMetrics: false,
                    maxThreats: 5,
                    maxCountries: 5,
                };

                const report = await analyticsService.generateReport(config);
                expect(report.metadata.timeRange).toBe(timeRange);
                expect(report.metadata.startTime).toBeLessThan(report.metadata.endTime);
            }
        });

        test('should emit reportGenerated event', async () => {
            const eventSpy = jest.fn();
            analyticsService.on('reportGenerated', eventSpy);

            const config: AnalyticsReportConfig = {
                timeRange: 'day',
                includeGeoDistribution: true,
                includeThreatSummary: true,
                includePerformanceMetrics: true,
                maxThreats: 10,
                maxCountries: 10,
            };

            await analyticsService.generateReport(config);

            expect(eventSpy).toHaveBeenCalledWith({
                config,
                report: expect.any(Object),
            });
        });
    });

    describe('getRealTimeDashboard', () => {
        test('should return real-time dashboard data', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 60,
                confidence: 0.8,
                reasons: [],
                fingerprint: 'test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 25.0,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('192.168.1.1', result, metrics, false);

            const dashboard = analyticsService.getRealTimeDashboard();

            expect(dashboard).toMatchObject({
                realTimeMetrics: expect.any(Object),
                detectionAnalytics: expect.any(Object),
                recentThreats: expect.any(Array),
                alertsCount: expect.any(Number),
            });

            expect(dashboard.detectionAnalytics.totalRequests).toBe(1);
            expect(dashboard.recentThreats).toHaveLength(1);
        });

        test('should calculate alerts count correctly', () => {
            // Add high-risk threat
            const highRiskResult: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 85,
                confidence: 0.9,
                reasons: [],
                fingerprint: 'high-risk',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('10.0.0.1', highRiskResult, metrics, true);

            const dashboard = analyticsService.getRealTimeDashboard();
            expect(dashboard.alertsCount).toBeGreaterThan(0);
        });
    });

    describe('generateThreatIntelligence', () => {
        test('should generate threat intelligence report', () => {
            // Setup multiple threats
            const threats = [
                { ip: '10.0.0.1', score: 80, types: ['fingerprint'] },
                { ip: '10.0.0.2', score: 60, types: ['behavioral'] },
                { ip: '10.0.0.3', score: 90, types: ['geographic'] },
            ];

            threats.forEach((threat, index) => {
                const result: DetectionResult = {
                    isSuspicious: true,
                    suspicionScore: threat.score,
                    confidence: 0.8,
                    reasons: threat.types.map(type => ({
                        category: type as any,
                        severity: 'high' as const,
                        description: `${type} threat`,
                        score: threat.score,
                    })),
                    fingerprint: `threat-${index}`,
                    metadata: {
                        timestamp: Date.now(),
                        processingTime: 25.0,
                        detectorVersions: { test: '1.0.0' },
                        geoData: {
                            country: index === 0 ? 'CN' : index === 1 ? 'RU' : 'US',
                            region: 'Test',
                            city: 'Test',
                            isVPN: false,
                            isProxy: false,
                            isHosting: false,
                            isTor: false,
                            riskScore: 30,
                            asn: 12345,
                            organization: 'Test ISP',
                        },
                    },
                };

                const metrics: PerformanceMetrics = {
                    totalProcessingTime: 25.0,
                    fingerprintingTime: 5.0,
                    behaviorAnalysisTime: 8.0,
                    geoAnalysisTime: 7.0,
                    scoringTime: 5.0,
                    memoryUsage: process.memoryUsage(),
                };

                // Record multiple requests for repeat offenders
                for (let i = 0; i < (index + 1) * 5; i++) {
                    metricsCollector.recordDetection(threat.ip, result, metrics, false);
                }
            });

            const intelligence = analyticsService.generateThreatIntelligence();

            expect(intelligence).toMatchObject({
                emergingThreats: expect.any(Array),
                repeatOffenders: expect.any(Array),
                geographicHotspots: expect.any(Array),
                attackPatterns: expect.any(Array),
            });

            expect(intelligence.repeatOffenders.length).toBeGreaterThan(0);
            expect(intelligence.attackPatterns.length).toBeGreaterThan(0);
            expect(intelligence.geographicHotspots.length).toBeGreaterThan(0);
        });
    });

    describe('getGeographicDistribution', () => {
        test('should analyze geographic distribution', () => {
            const countries = ['US', 'CN', 'RU', 'DE', 'FR'];

            countries.forEach((country, index) => {
                const result: DetectionResult = {
                    isSuspicious: index % 2 === 0,
                    suspicionScore: 30 + (index * 10),
                    confidence: 0.8,
                    reasons: [],
                    fingerprint: `geo-${index}`,
                    metadata: {
                        timestamp: Date.now(),
                        processingTime: 25.0,
                        detectorVersions: { test: '1.0.0' },
                        geoData: {
                            country,
                            region: 'Test',
                            city: 'Test',
                            isVPN: index === 1,
                            isProxy: index === 2,
                            isHosting: index === 3,
                            isTor: index === 4,
                            riskScore: 20 + (index * 5),
                            asn: 12345 + index,
                            organization: `ISP ${index}`,
                        },
                    },
                };

                const metrics: PerformanceMetrics = {
                    totalProcessingTime: 25.0,
                    fingerprintingTime: 5.0,
                    behaviorAnalysisTime: 8.0,
                    geoAnalysisTime: 7.0,
                    scoringTime: 5.0,
                    memoryUsage: process.memoryUsage(),
                };

                metricsCollector.recordDetection(`10.0.0.${index}`, result, metrics, false);
            });

            const geoDistribution = analyticsService.getGeographicDistribution();

            expect(geoDistribution.byCountry).toHaveLength(5);
            expect(geoDistribution.byCountry[0].percentage).toBeGreaterThan(0);
            expect(geoDistribution.byRiskLevel.low).toBeGreaterThanOrEqual(0);
            expect(geoDistribution.byRiskLevel.medium).toBeGreaterThanOrEqual(0);
            expect(geoDistribution.byRiskLevel.high).toBeGreaterThanOrEqual(0);
        });
    });

    describe('getPerformanceAnalysis', () => {
        test('should provide performance analysis', () => {
            // Add test data with varying performance
            const responseTimes = [10, 20, 30, 40, 50];

            responseTimes.forEach((time, index) => {
                const result: DetectionResult = {
                    isSuspicious: false,
                    suspicionScore: 15,
                    confidence: 0.8,
                    reasons: [],
                    fingerprint: `perf-${index}`,
                    metadata: {
                        timestamp: Date.now(),
                        processingTime: time,
                        detectorVersions: { test: '1.0.0' },
                    },
                };

                const metrics: PerformanceMetrics = {
                    totalProcessingTime: time,
                    fingerprintingTime: time * 0.2,
                    behaviorAnalysisTime: time * 0.3,
                    geoAnalysisTime: time * 0.3,
                    scoringTime: time * 0.2,
                    memoryUsage: process.memoryUsage(),
                };

                metricsCollector.recordDetection(`192.168.1.${index}`, result, metrics, false);
            });

            const performance = analyticsService.getPerformanceAnalysis();

            expect(performance).toMatchObject({
                responseTimePercentiles: {
                    p50: expect.any(Number),
                    p90: expect.any(Number),
                    p95: expect.any(Number),
                    p99: expect.any(Number),
                },
                throughputMetrics: {
                    requestsPerSecond: expect.any(Number),
                    peakRequestsPerSecond: expect.any(Number),
                    averageRequestsPerMinute: expect.any(Number),
                },
                resourceUtilization: {
                    averageMemoryUsage: expect.any(Number),
                    peakMemoryUsage: expect.any(Number),
                    averageCpuUsage: expect.any(Number),
                    cacheHitRate: expect.any(Number),
                },
                errorMetrics: {
                    errorRate: expect.any(Number),
                    errorCount: expect.any(Number),
                    errorsByComponent: expect.any(Object),
                },
            });
        });
    });

    describe('generateTrendAnalysis', () => {
        test('should generate trend analysis for different time ranges', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 50,
                confidence: 0.8,
                reasons: [],
                fingerprint: 'trend-test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 25.0,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('192.168.1.1', result, metrics, false);

            const trends = analyticsService.generateTrendAnalysis('day');

            expect(trends).toMatchObject({
                requestTrend: expect.any(Array),
                suspiciousTrend: expect.any(Array),
                performanceTrend: expect.any(Array),
                topGrowingThreats: expect.any(Array),
            });
        });
    });

    describe('exportData', () => {
        test('should export data in JSON format', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [],
                fingerprint: 'export-test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('10.0.0.1', result, metrics, true);

            const config: AnalyticsReportConfig = {
                timeRange: 'day',
                includeGeoDistribution: true,
                includeThreatSummary: true,
                includePerformanceMetrics: true,
                maxThreats: 10,
                maxCountries: 10,
            };

            const jsonData = analyticsService.exportData('json', config);
            expect(() => JSON.parse(jsonData)).not.toThrow();

            const parsed = JSON.parse(jsonData);
            expect(parsed.totalRequests).toBe(1);
            expect(parsed.suspiciousRequests).toBe(1);
        });

        test('should export data in CSV format', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [{ category: 'fingerprint', severity: 'high', description: 'Test', score: 75 }],
                fingerprint: 'csv-test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                    geoData: {
                        country: 'US',
                        region: 'CA',
                        city: 'San Francisco',
                        isVPN: false,
                        isProxy: false,
                        isHosting: false,
                        isTor: false,
                        riskScore: 10,
                        asn: 12345,
                        organization: 'Test ISP',
                    },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            metricsCollector.recordDetection('192.168.1.1', result, metrics, false);

            const config: AnalyticsReportConfig = {
                timeRange: 'day',
                includeGeoDistribution: true,
                includeThreatSummary: true,
                includePerformanceMetrics: true,
                maxThreats: 10,
                maxCountries: 10,
            };

            const csvData = analyticsService.exportData('csv', config);
            expect(csvData).toContain('IP,Country,Total Requests');
            expect(csvData).toContain('192.168.1.1,US,1');
        });

        test('should throw error for unsupported format', () => {
            const config: AnalyticsReportConfig = {
                timeRange: 'day',
                includeGeoDistribution: false,
                includeThreatSummary: false,
                includePerformanceMetrics: false,
                maxThreats: 10,
                maxCountries: 10,
            };

            expect(() => {
                analyticsService.exportData('xml' as any, config);
            }).toThrow('Unsupported export format: xml');
        });
    });

    describe('getIPAnalytics', () => {
        test('should provide IP-specific analytics', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 80,
                confidence: 0.9,
                reasons: [
                    { category: 'fingerprint', severity: 'high', description: 'Bot detected', score: 80 }
                ],
                fingerprint: 'ip-test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                    geoData: {
                        country: 'CN',
                        region: 'Beijing',
                        city: 'Beijing',
                        isVPN: true,
                        isProxy: false,
                        isHosting: false,
                        isTor: false,
                        riskScore: 40,
                        asn: 54321,
                        organization: 'VPN Provider',
                    },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            // Record multiple requests to build threat profile
            for (let i = 0; i < 5; i++) {
                metricsCollector.recordDetection('10.0.0.1', result, metrics, true);
            }

            const ipAnalytics = analyticsService.getIPAnalytics('10.0.0.1');

            expect(ipAnalytics).toMatchObject({
                threat: expect.any(Object),
                riskAssessment: {
                    riskLevel: expect.stringMatching(/^(low|medium|high)$/),
                    riskFactors: expect.any(Array),
                    recommendations: expect.any(Array),
                },
                historicalActivity: expect.any(Array),
            });

            expect(ipAnalytics.threat?.ip).toBe('10.0.0.1');
            expect(ipAnalytics.threat?.totalRequests).toBe(5);
            expect(ipAnalytics.riskAssessment.riskLevel).toBe('high');
            expect(ipAnalytics.riskAssessment.riskFactors.length).toBeGreaterThan(0);
        });

        test('should handle unknown IP', () => {
            const ipAnalytics = analyticsService.getIPAnalytics('192.168.1.100');

            expect(ipAnalytics.threat).toBeNull();
            expect(ipAnalytics.riskAssessment.riskLevel).toBe('low');
            expect(ipAnalytics.riskAssessment.riskFactors).toContain('No suspicious activity detected');
            expect(ipAnalytics.historicalActivity).toHaveLength(0);
        });
    });

    describe('clearCache', () => {
        test('should clear report cache', async () => {
            const config: AnalyticsReportConfig = {
                timeRange: 'hour',
                includeGeoDistribution: false,
                includeThreatSummary: false,
                includePerformanceMetrics: false,
                maxThreats: 5,
                maxCountries: 5,
            };

            // Generate report to populate cache
            await analyticsService.generateReport(config);

            const eventSpy = jest.fn();
            analyticsService.on('cacheCleared', eventSpy);

            analyticsService.clearCache();

            expect(eventSpy).toHaveBeenCalled();
        });
    });

    describe('event forwarding', () => {
        test('should forward metrics collector events', (done) => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [],
                fingerprint: 'event-test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 30.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            analyticsService.on('detectionEvent', (event) => {
                expect(event.ip).toBe('10.0.0.1');
                expect(event.result).toBe(result);
                done();
            });

            metricsCollector.recordDetection('10.0.0.1', result, metrics, false);
        });

        test('should forward error events', (done) => {
            const error = new Error('Test error');

            analyticsService.on('errorEvent', (event) => {
                expect(event.error).toBe(error);
                expect(event.component).toBe('testComponent');
                done();
            });

            metricsCollector.recordError(error, 'testComponent');
        });
    });
});

describe('getAnalyticsService singleton', () => {
    test('should return same instance on multiple calls', () => {
        const service1 = getAnalyticsService();
        const service2 = getAnalyticsService();

        expect(service1).toBe(service2);
    });

    afterEach(() => {
        // Clean up singleton
        const service = getAnalyticsService();
        service.removeAllListeners();
        service.clearCache();
    });
});