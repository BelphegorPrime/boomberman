import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import {
    MetricsCollector,
    getMetricsCollector,
    type RealTimeMetrics,
    type HistoricalMetrics,
    type PerformanceMetrics
} from '../src/utils/logger/metricsCollector.js';
import type { DetectionResult } from '../src/detection/types/DetectionResult.js';

// Mock process methods
const mockMemoryUsage = jest.fn(() => ({
    rss: 1000000,
    heapUsed: 500000,
    heapTotal: 800000,
    external: 100000,
    arrayBuffers: 50000,
}));

const mockCpuUsage = jest.fn(() => ({
    user: 1000000,
    system: 500000,
}));

Object.defineProperty(process, 'memoryUsage', { value: mockMemoryUsage });
Object.defineProperty(process, 'cpuUsage', { value: mockCpuUsage });

describe('MetricsCollector', () => {
    let collector: MetricsCollector;

    beforeEach(() => {
        jest.clearAllMocks();
        collector = new MetricsCollector();
    });

    afterEach(() => {
        collector.removeAllListeners();
    });

    describe('recordDetection', () => {
        test('should record legitimate detection event', () => {
            const result: DetectionResult = {
                isSuspicious: false,
                suspicionScore: 15,
                confidence: 0.8,
                reasons: [],
                fingerprint: 'legitimate-fingerprint',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                    geoData: {
                        country: 'US',
                        region: 'CA',
                        city: 'San Francisco',
                        isVPN: false,
                        isProxy: false,
                        isHosting: false,
                        isTor: false,
                        riskScore: 5,
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

            const eventSpy = jest.fn();
            collector.on('detection', eventSpy);

            collector.recordDetection('192.168.1.1', result, metrics, false);

            expect(eventSpy).toHaveBeenCalledWith({
                ip: '192.168.1.1',
                result,
                metrics,
                blocked: false,
            });

            const analytics = collector.getDetectionAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(0);
            expect(analytics.geoDistribution.US).toBe(1);
        });

        test('should record suspicious detection event', () => {
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

            collector.recordDetection('10.0.0.1', result, metrics, true);

            const analytics = collector.getDetectionAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(1);
            expect(analytics.blockedRequests).toBe(1);
            expect(analytics.geoDistribution.CN).toBe(1);
            expect(analytics.topThreats).toHaveLength(1);
            expect(analytics.topThreats[0].ip).toBe('10.0.0.1');
        });

        test('should update threat summaries correctly', () => {
            const result1: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 60,
                confidence: 0.8,
                reasons: [{ category: 'fingerprint', severity: 'medium', description: 'Test', score: 60 }],
                fingerprint: 'test-1',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
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

            const result2: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 80,
                confidence: 0.9,
                reasons: [{ category: 'behavioral', severity: 'high', description: 'Test', score: 80 }],
                fingerprint: 'test-2',
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
                totalProcessingTime: 25.0,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            // Record two detections from same IP
            collector.recordDetection('192.168.1.1', result1, metrics, false);
            collector.recordDetection('192.168.1.1', result2, metrics, false);

            const analytics = collector.getDetectionAnalytics();
            const threat = analytics.topThreats.find(t => t.ip === '192.168.1.1');

            expect(threat).toBeDefined();
            expect(threat!.totalRequests).toBe(2);
            expect(threat!.averageScore).toBe(70); // (60 + 80) / 2
            expect(threat!.threatTypes).toContain('fingerprint');
            expect(threat!.threatTypes).toContain('behavioral');
        });
    });

    describe('recordError', () => {
        test('should record error events', () => {
            const error = new Error('Test error');
            const eventSpy = jest.fn();
            collector.on('error', eventSpy);

            collector.recordError(error, 'testComponent');

            expect(eventSpy).toHaveBeenCalledWith({
                error,
                component: 'testComponent',
                timestamp: expect.any(Number),
            });
        });
    });

    describe('recordCacheEvent', () => {
        test('should record cache hits and misses', () => {
            collector.recordCacheEvent(true);
            collector.recordCacheEvent(true);
            collector.recordCacheEvent(false);

            const metrics = collector.getRealTimeMetrics();
            expect(metrics.cacheHitRate).toBeCloseTo(2 / 3, 2);
        });

        test('should handle zero cache events', () => {
            const metrics = collector.getRealTimeMetrics();
            expect(metrics.cacheHitRate).toBe(0);
        });
    });

    describe('getRealTimeMetrics', () => {
        test('should return real-time metrics', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
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

            collector.recordDetection('192.168.1.1', result, metrics, false);
            collector.recordCacheEvent(true);

            const realTimeMetrics = collector.getRealTimeMetrics();

            expect(realTimeMetrics).toMatchObject({
                requestsPerSecond: expect.any(Number),
                averageResponseTime: expect.any(Number),
                suspiciousRequestRate: expect.any(Number),
                errorRate: expect.any(Number),
                memoryUsage: expect.any(Object),
                cpuUsage: expect.any(Number),
                activeConnections: expect.any(Number),
                cacheHitRate: expect.any(Number),
            });

            expect(realTimeMetrics.averageResponseTime).toBe(25.0);
            expect(realTimeMetrics.suspiciousRequestRate).toBe(1.0);
            expect(realTimeMetrics.cacheHitRate).toBe(1.0);
        });

        test('should handle empty metrics gracefully', () => {
            const metrics = collector.getRealTimeMetrics();

            expect(metrics.requestsPerSecond).toBe(0);
            expect(metrics.averageResponseTime).toBe(0);
            expect(metrics.suspiciousRequestRate).toBe(0);
            expect(metrics.errorRate).toBe(0);
            expect(metrics.cacheHitRate).toBe(0);
        });
    });

    describe('getHistoricalMetrics', () => {
        test('should return historical metrics structure', () => {
            const historical = collector.getHistoricalMetrics();

            expect(historical).toMatchObject({
                hourlyStats: expect.any(Array),
                dailyStats: expect.any(Array),
                topThreats: expect.any(Array),
                geoDistribution: expect.any(Object),
                detectionAccuracy: expect.any(Number),
                falsePositiveRate: expect.any(Number),
            });
        });
    });

    describe('getDetectionAnalytics', () => {
        test('should return comprehensive analytics', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [],
                fingerprint: 'test',
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

            collector.recordDetection('192.168.1.1', result, metrics, true);

            const analytics = collector.getDetectionAnalytics();

            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(1);
            expect(analytics.blockedRequests).toBe(1);
            expect(analytics.averageProcessingTime).toBe(30.0);
            expect(analytics.topThreats).toHaveLength(1);
            expect(analytics.geoDistribution.US).toBe(1);
        });
    });

    describe('reset', () => {
        test('should reset all metrics', () => {
            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
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

            // Add some data
            collector.recordDetection('192.168.1.1', result, metrics, false);
            collector.recordError(new Error('test'));
            collector.recordCacheEvent(true);

            // Verify data exists
            let analytics = collector.getDetectionAnalytics();
            expect(analytics.totalRequests).toBe(1);

            // Reset and verify
            collector.reset();
            analytics = collector.getDetectionAnalytics();

            expect(analytics.totalRequests).toBe(0);
            expect(analytics.suspiciousRequests).toBe(0);
            expect(analytics.blockedRequests).toBe(0);
            expect(analytics.topThreats).toHaveLength(0);
            expect(Object.keys(analytics.geoDistribution)).toHaveLength(0);

            const realTime = collector.getRealTimeMetrics();
            expect(realTime.cacheHitRate).toBe(0);
        });
    });

    describe('event emission', () => {
        test('should emit detection events', (done) => {
            const result: DetectionResult = {
                isSuspicious: false,
                suspicionScore: 15,
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

            collector.on('detection', (event) => {
                expect(event.ip).toBe('192.168.1.1');
                expect(event.result).toBe(result);
                expect(event.metrics).toBe(metrics);
                expect(event.blocked).toBe(false);
                done();
            });

            collector.recordDetection('192.168.1.1', result, metrics, false);
        });

        test('should emit error events', (done) => {
            const error = new Error('Test error');

            collector.on('error', (event) => {
                expect(event.error).toBe(error);
                expect(event.component).toBe('testComponent');
                expect(event.timestamp).toBeGreaterThan(0);
                done();
            });

            collector.recordError(error, 'testComponent');
        });
    });

    describe('performance calculations', () => {
        test('should calculate accurate averages', () => {
            const metrics1: PerformanceMetrics = {
                totalProcessingTime: 20.0,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 5.0,
                geoAnalysisTime: 5.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            const metrics2: PerformanceMetrics = {
                totalProcessingTime: 30.0,
                fingerprintingTime: 10.0,
                behaviorAnalysisTime: 10.0,
                geoAnalysisTime: 5.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            const result: DetectionResult = {
                isSuspicious: false,
                suspicionScore: 15,
                confidence: 0.8,
                reasons: [],
                fingerprint: 'test',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            collector.recordDetection('192.168.1.1', result, metrics1, false);
            collector.recordDetection('192.168.1.2', result, metrics2, false);

            const analytics = collector.getDetectionAnalytics();
            expect(analytics.averageProcessingTime).toBe(25.0); // (20 + 30) / 2
        });
    });
});

describe('getMetricsCollector singleton', () => {
    test('should return same instance on multiple calls', () => {
        const collector1 = getMetricsCollector();
        const collector2 = getMetricsCollector();

        expect(collector1).toBe(collector2);
    });
});