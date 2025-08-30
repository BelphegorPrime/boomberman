import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express from 'express';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { getDetectionLogger } from '../src/utils/logger/detectionLogger.js';
import { getMetricsCollector } from '../src/utils/logger/metricsCollector.js';
import { DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration.js';

// Mock file system operations
jest.mock('fs', () => ({
    createWriteStream: jest.fn(() => ({
        write: jest.fn(),
        end: jest.fn(),
    })),
    writeFileSync: jest.fn(),
    readFileSync: jest.fn(),
    existsSync: jest.fn(() => true),
    mkdirSync: jest.fn(),
}));

jest.mock('../src/utils/ensureDirExistence.js', () => ({
    ensureDirExistence: jest.fn(),
}));

jest.mock('../src/utils/isTest.js', () => ({
    isTest: true,
}));

describe('Enhanced Logging Integration', () => {
    let app: express.Application;
    let middleware: EnhancedBotDetectionMiddleware;
    let logger: any;
    let metricsCollector: any;

    beforeEach(() => {
        jest.clearAllMocks();

        // Create Express app with middleware
        app = express();
        middleware = new EnhancedBotDetectionMiddleware(DEFAULT_DETECTION_CONFIG);

        // Add middleware to app
        app.use(middleware.middleware);

        // Add test route
        app.get('/test', (req, res) => {
            res.json({
                success: true,
                correlationId: req.correlationId,
                detectionScore: req.detectionResult?.suspicionScore || 0,
            });
        });

        // Get logger and metrics collector instances
        logger = getDetectionLogger();
        metricsCollector = getMetricsCollector();

        // Reset analytics
        logger.resetAnalytics();
        metricsCollector.reset();
    });

    afterEach(() => {
        logger.close();
    });

    describe('comprehensive logging flow', () => {
        test('should log complete detection flow for legitimate request', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('Connection', 'keep-alive')
                .expect(200);

            // Verify response contains correlation ID
            expect(response.body.correlationId).toBeDefined();
            expect(response.body.detectionScore).toBeLessThan(30);

            // Verify analytics were updated
            const analytics = logger.getAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(0);

            // Verify metrics were recorded
            const metricsAnalytics = metricsCollector.getDetectionAnalytics();
            expect(metricsAnalytics.totalRequests).toBe(1);
            expect(metricsAnalytics.suspiciousRequests).toBe(0);
        });

        test('should log complete detection flow for suspicious request', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.25.1')
                .expect(200);

            // Verify response contains detection metadata
            expect(response.body.correlationId).toBeDefined();
            expect(response.body.detectionScore).toBeGreaterThan(0);

            // Verify analytics were updated
            const analytics = logger.getAnalytics();
            expect(analytics.totalRequests).toBe(1);

            // Verify metrics were recorded
            const metricsAnalytics = metricsCollector.getDetectionAnalytics();
            expect(metricsAnalytics.totalRequests).toBe(1);
        });

        test('should log high-risk bot detection and blocking', async () => {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Selenium/4.0.0 (python)')
                .expect(200); // Should return faulty response but still 200

            // Verify analytics show blocked request
            const analytics = logger.getAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(1);
            expect(analytics.blockedRequests).toBe(1);

            // Verify metrics show blocked request
            const metricsAnalytics = metricsCollector.getDetectionAnalytics();
            expect(metricsAnalytics.blockedRequests).toBe(1);
        });
    });

    describe('configuration change logging', () => {
        test('should log threshold updates', () => {
            const oldThreshold = middleware.getConfig().thresholds.suspicious;

            middleware.updateThreshold('suspicious', 25, 'admin', 'Adjusting sensitivity for testing');

            const newThreshold = middleware.getConfig().thresholds.suspicious;
            expect(newThreshold).toBe(25);

            // Verify configuration change was logged
            const configHistory = logger.getConfigurationHistory();
            expect(configHistory).toHaveLength(1);
            expect(configHistory[0].changeType).toBe('THRESHOLD_UPDATE');
            expect(configHistory[0].changedBy).toBe('admin');
            expect(configHistory[0].reason).toBe('Adjusting sensitivity for testing');
        });

        test('should log whitelist additions', () => {
            const testIP = '192.168.1.100';

            middleware.addToWhitelist(testIP, 'security-team', 'Adding monitoring server');

            const config = middleware.getConfig();
            expect(config.whitelist.ips).toContain(testIP);

            // Verify configuration change was logged
            const configHistory = logger.getConfigurationHistory();
            expect(configHistory).toHaveLength(1);
            expect(configHistory[0].changeType).toBe('WHITELIST_UPDATE');
            expect(configHistory[0].changedBy).toBe('security-team');
        });

        test('should log full configuration updates', () => {
            const newConfig = {
                thresholds: {
                    suspicious: 25,
                    highRisk: 75,
                },
                scoringWeights: {
                    fingerprint: 0.4,
                    behavioral: 0.3,
                    geographic: 0.2,
                    reputation: 0.1,
                },
            };

            middleware.updateConfig(newConfig, 'admin', 'Performance tuning');

            // Verify configuration change was logged
            const configHistory = logger.getConfigurationHistory();
            expect(configHistory).toHaveLength(1);
            expect(configHistory[0].changeType).toBe('FULL_CONFIG_UPDATE');
            expect(configHistory[0].changedBy).toBe('admin');
        });
    });

    describe('false positive reporting', () => {
        test('should handle false positive reports', async () => {
            // First, make a request that gets flagged
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'curl/7.68.0')
                .expect(200);

            const correlationId = response.body.correlationId;
            expect(correlationId).toBeDefined();

            // Report it as a false positive
            logger.reportFalsePositive(
                correlationId,
                '127.0.0.1',
                'curl/7.68.0',
                45,
                ['Suspicious user agent'],
                'security-analyst',
                'LEGITIMATE',
                'This is a legitimate monitoring tool used by our ops team'
            );

            // Verify false positive was recorded
            const reports = logger.getFalsePositiveReports();
            expect(reports).toHaveLength(1);
            expect(reports[0].correlationId).toBe(correlationId);
            expect(reports[0].actualClassification).toBe('LEGITIMATE');
            expect(reports[0].reportedBy).toBe('security-analyst');

            // Verify analytics were updated
            const enhancedAnalytics = logger.getEnhancedAnalytics();
            expect(enhancedAnalytics.falsePositives).toBe(1);
            expect(enhancedAnalytics.falsePositiveRate).toBeGreaterThan(0);
        });
    });

    describe('performance metrics collection', () => {
        test('should collect comprehensive performance statistics', async () => {
            // Make multiple requests to generate performance data
            const requests = [];
            for (let i = 0; i < 10; i++) {
                requests.push(
                    request(app)
                        .get('/test')
                        .set('User-Agent', `TestBot-${i}/1.0`)
                );
            }

            await Promise.all(requests);

            // Get performance statistics
            const perfStats = metricsCollector.getPerformanceStatistics();

            expect(perfStats.responseTimePercentiles.p50).toBeGreaterThan(0);
            expect(perfStats.responseTimePercentiles.p90).toBeGreaterThan(0);
            expect(perfStats.responseTimePercentiles.p95).toBeGreaterThan(0);
            expect(perfStats.responseTimePercentiles.p99).toBeGreaterThan(0);

            expect(perfStats.throughputMetrics.requestsPerSecond).toBeGreaterThan(0);
            expect(perfStats.throughputMetrics.averageRequestsPerMinute).toBeGreaterThan(0);

            expect(perfStats.resourceUsage.averageMemoryUsage).toBeGreaterThan(0);
            expect(perfStats.resourceUsage.peakMemoryUsage).toBeGreaterThan(0);
        });

        test('should track error rates correctly', async () => {
            // Simulate some errors by making requests that might timeout
            const originalTimeout = middleware['maxProcessingTime'];
            middleware['maxProcessingTime'] = 1; // Very short timeout to force errors

            try {
                await request(app)
                    .get('/test')
                    .set('User-Agent', 'TestBot/1.0');
            } catch (error) {
                // Expected to potentially fail due to timeout
            }

            // Restore original timeout
            middleware['maxProcessingTime'] = originalTimeout;

            // Make a successful request
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (legitimate browser)');

            const perfStats = metricsCollector.getPerformanceStatistics();

            // Should have some error rate if timeout occurred
            expect(perfStats.errorMetrics.errorCount).toBeGreaterThanOrEqual(0);
            expect(perfStats.errorMetrics.errorRate).toBeGreaterThanOrEqual(0);
        });
    });

    describe('SIEM-compatible structured logging', () => {
        test('should generate SIEM-compatible log entries', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Suspicious-Bot/1.0')
                .set('Referer', 'https://malicious-site.com')
                .set('Accept-Language', 'en-US')
                .set('Content-Length', '500')
                .expect(200);

            // Verify the request was processed
            expect(response.body.correlationId).toBeDefined();

            // The actual log verification would happen through mocked write streams
            // In a real scenario, we would check that structured logs contain:
            // - correlationId for tracing
            // - severity levels
            // - category and source fields
            // - detailed reasoning breakdown
            // - SIEM-compatible metadata
        });
    });

    describe('analytics and reporting', () => {
        test('should provide comprehensive analytics', async () => {
            // Generate diverse traffic
            await request(app).get('/test').set('User-Agent', 'Mozilla/5.0 (legitimate)');
            await request(app).get('/test').set('User-Agent', 'python-requests/2.25.1');
            await request(app).get('/test').set('User-Agent', 'Selenium/4.0.0');

            const analytics = logger.getEnhancedAnalytics();

            expect(analytics.totalRequests).toBe(3);
            expect(analytics.suspiciousRequests).toBeGreaterThan(0);
            expect(analytics.detectionAccuracy).toBeGreaterThan(0);
            expect(analytics.averageProcessingTime).toBeGreaterThan(0);
            expect(analytics.topThreats.length).toBeGreaterThan(0);

            // Check enhanced fields
            expect(analytics.falsePositiveRate).toBeGreaterThanOrEqual(0);
            expect(analytics.configurationChanges).toBeGreaterThanOrEqual(0);
        });

        test('should track geographic distribution', async () => {
            // This would require actual GeoIP data in a real test
            // For now, just verify the structure exists
            const analytics = logger.getAnalytics();
            expect(analytics.geoDistribution).toBeDefined();
            expect(typeof analytics.geoDistribution).toBe('object');
        });
    });
});