import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import {
    DetectionLogger,
    getDetectionLogger,
    createPerformanceMetrics,
    type CorrelationContext,
    type DetectionLogEntry,
    type PerformanceMetrics
} from '../src/utils/logger/detectionLogger.js';
import type { DetectionResult } from '../src/detection/types/DetectionResult.js';

// Mock ensureDirExistence
jest.mock('../src/utils/ensureDirExistence.js', () => ({
    ensureDirExistence: jest.fn(),
}));

// Mock isTest
jest.mock('../src/utils/isTest.js', () => ({
    isTest: true,
}));

// Mock fs module
const mockCreateWriteStream = jest.fn();
jest.mock('fs', () => ({
    createWriteStream: mockCreateWriteStream,
    writeFileSync: jest.fn(),
    readFileSync: jest.fn(),
    existsSync: jest.fn(() => true),
    mkdirSync: jest.fn(),
}));

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

describe('DetectionLogger', () => {
    let logger: DetectionLogger;
    let mockWriteStream: any;
    let mockMetricsStream: any;
    let mockAuditStream: any;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();

        // Mock write streams
        mockWriteStream = {
            write: jest.fn(),
            end: jest.fn(),
        };

        mockMetricsStream = {
            write: jest.fn(),
            end: jest.fn(),
        };

        mockAuditStream = {
            write: jest.fn(),
            end: jest.fn(),
        };

        mockCreateWriteStream.mockImplementation((filePath: string) => {
            if (filePath.includes('metrics')) {
                return mockMetricsStream;
            }
            if (filePath.includes('audit')) {
                return mockAuditStream;
            }
            return mockWriteStream;
        });

        // Create new logger instance
        logger = new DetectionLogger();
    });

    afterEach(() => {
        logger.close();
    });

    describe('createCorrelationContext', () => {
        test('should create correlation context with required fields', () => {
            const mockReq = {
                ip: '192.168.1.1',
                get: jest.fn().mockReturnValue('Mozilla/5.0'),
                sessionID: 'session123',
            };

            const context = logger.createCorrelationContext(mockReq);

            expect(context).toMatchObject({
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                sessionId: 'session123',
            });
            expect(context.correlationId).toBeDefined();
            expect(context.requestId).toBeDefined();
            expect(context.timestamp).toBeGreaterThan(0);
        });

        test('should handle missing request properties gracefully', () => {
            const mockReq = {
                connection: { remoteAddress: '10.0.0.1' },
                get: jest.fn().mockReturnValue(undefined),
            };

            const context = logger.createCorrelationContext(mockReq);

            expect(context.ip).toBe('10.0.0.1');
            expect(context.userAgent).toBe('unknown');
            expect(context.sessionId).toBeUndefined();
        });
    });

    describe('logDetectionStart', () => {
        test('should log detection start event', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                sessionId: 'sess-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const mockReq = {
                path: '/api/test',
                method: 'GET',
                headers: { 'user-agent': 'Mozilla/5.0' },
                query: { param: 'value' },
            };

            logger.logDetectionStart(context, mockReq);

            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"DETECTION_START"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"correlationId":"corr-123"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"ip":"192.168.1.1"')
            );
        });

        test('should increment total requests counter', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const mockReq = { path: '/test', method: 'GET', headers: {}, query: {} };

            const initialAnalytics = logger.getAnalytics();
            logger.logDetectionStart(context, mockReq);
            const updatedAnalytics = logger.getAnalytics();

            expect(updatedAnalytics.totalRequests).toBe(initialAnalytics.totalRequests + 1);
        });
    });

    describe('logDetectionComplete', () => {
        test('should log legitimate request completion', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const result: DetectionResult = {
                isSuspicious: false,
                suspicionScore: 15,
                confidence: 0.8,
                reasons: [],
                fingerprint: 'test-fingerprint',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.5,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const metrics: PerformanceMetrics = {
                totalProcessingTime: 25.5,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.5,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            const mockReq = { path: '/test', method: 'GET' };

            logger.logDetectionComplete(context, result, metrics, mockReq);

            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"LEGITIMATE_REQUEST_PROCESSED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"info"')
            );
        });

        test('should log suspicious request completion', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Bot/1.0',
                timestamp: Date.now(),
            };

            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [
                    {
                        category: 'fingerprint',
                        severity: 'high',
                        description: 'Automation framework detected',
                        score: 80,
                    },
                ],
                fingerprint: 'bot-fingerprint',
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

            const mockReq = { path: '/test', method: 'GET' };

            logger.logDetectionComplete(context, result, metrics, mockReq);

            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"SUSPICIOUS_REQUEST_DETECTED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"warn"')
            );
        });

        test('should update analytics and threat summaries', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Bot/1.0',
                timestamp: Date.now(),
            };

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

            const mockReq = { path: '/test', method: 'GET' };

            const initialAnalytics = logger.getAnalytics();
            logger.logDetectionComplete(context, result, metrics, mockReq);
            const updatedAnalytics = logger.getAnalytics();

            expect(updatedAnalytics.suspiciousRequests).toBe(initialAnalytics.suspiciousRequests + 1);
            expect(updatedAnalytics.geoDistribution.US).toBe(1);
            expect(updatedAnalytics.topThreats).toHaveLength(1);
            expect(updatedAnalytics.topThreats[0].ip).toBe('192.168.1.1');
        });
    });

    describe('logDetectionError', () => {
        test('should log detection errors with context', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const error = new Error('Test error');
            error.stack = 'Error: Test error\n    at test';

            const mockReq = { path: '/test', method: 'GET' };

            logger.logDetectionError(context, error, mockReq, 'testComponent');

            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"DETECTION_ERROR"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"error"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"error":"Test error"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"component":"testComponent"')
            );
        });
    });

    describe('logThreatAction', () => {
        test('should log threat actions with detection result', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Bot/1.0',
                timestamp: Date.now(),
            };

            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 85,
                confidence: 0.95,
                reasons: [
                    {
                        category: 'fingerprint',
                        severity: 'high',
                        description: 'Automation detected',
                        score: 85,
                    },
                ],
                fingerprint: 'bot-fingerprint',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const mockReq = { path: '/test', method: 'GET' };

            logger.logThreatAction(context, 'BANNED', result, mockReq);

            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"THREAT_ACTION_BANNED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"warn"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"action":"BANNED"')
            );
        });

        test('should increment blocked requests counter', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Bot/1.0',
                timestamp: Date.now(),
            };

            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 85,
                confidence: 0.95,
                reasons: [],
                fingerprint: 'bot-fingerprint',
                metadata: {
                    timestamp: Date.now(),
                    processingTime: 25.0,
                    detectorVersions: { test: '1.0.0' },
                },
            };

            const mockReq = { path: '/test', method: 'GET' };

            const initialAnalytics = logger.getAnalytics();
            logger.logThreatAction(context, 'BLOCKED', result, mockReq);
            const updatedAnalytics = logger.getAnalytics();

            expect(updatedAnalytics.blockedRequests).toBe(initialAnalytics.blockedRequests + 1);
        });
    });

    describe('performance metrics', () => {
        test('should log performance summary', () => {
            // Add some performance data
            const metrics: PerformanceMetrics = {
                totalProcessingTime: 25.0,
                fingerprintingTime: 5.0,
                behaviorAnalysisTime: 8.0,
                geoAnalysisTime: 7.0,
                scoringTime: 5.0,
                memoryUsage: process.memoryUsage(),
            };

            // Access private method for testing
            (logger as any).recordPerformanceMetrics(metrics);
            logger.logPerformanceSummary();

            expect(mockMetricsStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"PERFORMANCE_SUMMARY"')
            );
        });
    });

    describe('analytics', () => {
        test('should provide accurate analytics data', () => {
            const analytics = logger.getAnalytics();

            expect(analytics).toMatchObject({
                totalRequests: expect.any(Number),
                suspiciousRequests: expect.any(Number),
                blockedRequests: expect.any(Number),
                falsePositives: expect.any(Number),
                detectionAccuracy: expect.any(Number),
                averageProcessingTime: expect.any(Number),
                topThreats: expect.any(Array),
                geoDistribution: expect.any(Object),
            });
        });

        test('should reset analytics correctly', () => {
            // Add some data first
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const mockReq = { path: '/test', method: 'GET', headers: {}, query: {} };
            logger.logDetectionStart(context, mockReq);

            // Reset and verify
            logger.resetAnalytics();
            const analytics = logger.getAnalytics();

            expect(analytics.totalRequests).toBe(0);
            expect(analytics.suspiciousRequests).toBe(0);
            expect(analytics.blockedRequests).toBe(0);
            expect(analytics.topThreats).toHaveLength(0);
        });
    });

    describe('header sanitization', () => {
        test('should sanitize sensitive headers', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            const mockReq = {
                path: '/test',
                method: 'GET',
                headers: {
                    'user-agent': 'Mozilla/5.0',
                    'authorization': 'Bearer secret-token',
                    'cookie': 'session=secret',
                    'x-api-key': 'api-key-123',
                },
                query: {},
            };

            logger.logDetectionStart(context, mockReq);

            const logCall = mockWriteStream.write.mock.calls[0][0];
            const logEntry = JSON.parse(logCall);

            expect(logEntry.metadata.headers.authorization).toBe('[REDACTED]');
            expect(logEntry.metadata.headers.cookie).toBe('[REDACTED]');
            expect(logEntry.metadata.headers['x-api-key']).toBe('[REDACTED]');
            expect(logEntry.metadata.headers['user-agent']).toBe('Mozilla/5.0');
        });
    });

    describe('enhanced logging features', () => {
        test('should log configuration changes', () => {
            const correlationId = 'config-123';
            const oldValue = { threshold: 30 };
            const newValue = { threshold: 40 };

            logger.logConfigurationChange(
                correlationId,
                'THRESHOLD_UPDATE',
                oldValue,
                newValue,
                'admin',
                'Adjusting sensitivity'
            );

            // Check that audit entry was written
            expect(mockAuditStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"CONFIGURATION_CHANGE"')
            );
            expect(mockAuditStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"changedBy":"admin"')
            );

            // Check configuration history
            const history = logger.getConfigurationHistory();
            expect(history).toHaveLength(1);
            expect(history[0].changeType).toBe('THRESHOLD_UPDATE');
            expect(history[0].changedBy).toBe('admin');
        });

        test('should report false positives', () => {
            const correlationId = 'fp-123';
            const ip = '192.168.1.1';
            const userAgent = 'Mozilla/5.0';

            logger.reportFalsePositive(
                correlationId,
                ip,
                userAgent,
                75,
                ['Automation detected'],
                'security-team',
                'LEGITIMATE',
                'This was a legitimate monitoring tool'
            );

            // Check that false positive was logged
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"FALSE_POSITIVE_REPORTED"')
            );

            // Check false positive reports
            const reports = logger.getFalsePositiveReports();
            expect(reports).toHaveLength(1);
            expect(reports[0].actualClassification).toBe('LEGITIMATE');
            expect(reports[0].reportedBy).toBe('security-team');

            // Check that analytics were updated
            const analytics = logger.getAnalytics();
            expect(analytics.falsePositives).toBe(1);
        });

        test('should generate detailed reasoning', () => {
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Bot/1.0',
                timestamp: Date.now(),
            };

            const result: DetectionResult = {
                isSuspicious: true,
                suspicionScore: 75,
                confidence: 0.9,
                reasons: [
                    {
                        category: 'fingerprint',
                        severity: 'high',
                        description: 'Missing browser headers',
                        score: 40,
                    },
                    {
                        category: 'behavioral',
                        severity: 'medium',
                        description: 'Fast request timing',
                        score: 35,
                    },
                ],
                fingerprint: 'bot-fingerprint',
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

            const mockReq = {
                path: '/test',
                method: 'GET',
                headers: {
                    'content-length': '100',
                    'referer': 'https://example.com',
                    'accept-language': 'en-US',
                    'accept-encoding': 'gzip',
                },
            };

            logger.logDetectionComplete(context, result, metrics, mockReq);

            const logCall = mockWriteStream.write.mock.calls[0][0];
            const logEntry = JSON.parse(logCall);

            // Check SIEM-compatible fields
            expect(logEntry.metadata.severity).toBe('high');
            expect(logEntry.metadata.category).toBe('security.detection');
            expect(logEntry.metadata.source).toBe('enhanced-bot-detection');

            // Check detailed reasoning
            expect(logEntry.metadata.detailedReasoning).toBeDefined();
            expect(logEntry.metadata.detailedReasoning.overallScore).toBe(75);
            expect(logEntry.metadata.detailedReasoning.recommendedAction).toBe('RATE_LIMIT');
            expect(logEntry.metadata.detailedReasoning.riskFactors).toContain('Missing browser headers');

            // Check additional context fields
            expect(logEntry.metadata.requestSize).toBe('100');
            expect(logEntry.metadata.referer).toBe('https://example.com');
            expect(logEntry.metadata.acceptLanguage).toBe('en-US');
        });

        test('should provide enhanced analytics', () => {
            // Add some test data
            const context: CorrelationContext = {
                correlationId: 'corr-123',
                requestId: 'req-123',
                ip: '192.168.1.1',
                userAgent: 'Mozilla/5.0',
                timestamp: Date.now(),
            };

            logger.logConfigurationChange(
                'config-123',
                'THRESHOLD_UPDATE',
                { threshold: 30 },
                { threshold: 40 },
                'admin'
            );

            logger.reportFalsePositive(
                'fp-123',
                '192.168.1.1',
                'Mozilla/5.0',
                75,
                ['Test'],
                'admin',
                'LEGITIMATE',
                'Test report'
            );

            const enhancedAnalytics = logger.getEnhancedAnalytics();

            expect(enhancedAnalytics.falsePositiveRate).toBeGreaterThan(0);
            expect(enhancedAnalytics.configurationChanges).toBe(1);
            expect(enhancedAnalytics.lastConfigurationChange).toBeDefined();
        });
    });
});

describe('createPerformanceMetrics', () => {
    test('should create performance metrics with all fields', () => {
        const startCpuUsage = { user: 1000000, system: 500000 };

        const metrics = createPerformanceMetrics(
            25.5,
            5.0,
            8.0,
            7.5,
            5.0,
            startCpuUsage
        );

        expect(metrics).toMatchObject({
            totalProcessingTime: 25.5,
            fingerprintingTime: 5.0,
            behaviorAnalysisTime: 8.0,
            geoAnalysisTime: 7.5,
            scoringTime: 5.0,
            memoryUsage: expect.any(Object),
            cpuUsage: expect.any(Object),
        });
    });

    test('should create performance metrics with defaults', () => {
        const metrics = createPerformanceMetrics(25.5);

        expect(metrics).toMatchObject({
            totalProcessingTime: 25.5,
            fingerprintingTime: 0,
            behaviorAnalysisTime: 0,
            geoAnalysisTime: 0,
            scoringTime: 0,
            memoryUsage: expect.any(Object),
        });
        expect(metrics.cpuUsage).toBeUndefined();
    });
});

describe('getDetectionLogger singleton', () => {
    test('should return same instance on multiple calls', () => {
        const logger1 = getDetectionLogger();
        const logger2 = getDetectionLogger();

        expect(logger1).toBe(logger2);
    });
});