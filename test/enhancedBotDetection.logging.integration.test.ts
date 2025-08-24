import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express from 'express';
import fs from 'fs';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { getDetectionLogger } from '../src/utils/logger/detectionLogger.js';
import { getMetricsCollector } from '../src/utils/logger/metricsCollector.js';
import { DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration.js';

// Mock fs module
jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

describe('Enhanced Bot Detection Logging Integration', () => {
    let app: express.Application;
    let middleware: EnhancedBotDetectionMiddleware;
    let mockWriteStream: any;
    let mockMetricsStream: any;

    beforeEach(() => {
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

        mockFs.createWriteStream.mockImplementation((filePath: string) => {
            if (filePath.includes('metrics')) {
                return mockMetricsStream as any;
            }
            return mockWriteStream as any;
        });

        // Create Express app with middleware
        app = express();
        middleware = new EnhancedBotDetectionMiddleware({
            ...DEFAULT_DETECTION_CONFIG,
            enabled: true,
            thresholds: {
                suspicious: 30,
                highRisk: 70,
            },
        });

        app.use(middleware.middleware);

        // Test route
        app.get('/test', (req, res) => {
            res.json({
                success: true,
                correlationId: req.correlationId,
                detectionScore: req.detectionResult?.suspicionScore,
            });
        });

        // Reset logger analytics
        getDetectionLogger().resetAnalytics();
        getMetricsCollector().reset();
    });

    afterEach(() => {
        getDetectionLogger().close();
    });

    describe('legitimate request logging', () => {
        test('should log legitimate request with correlation ID', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('Connection', 'keep-alive')
                .expect(200);

            // Verify response includes correlation ID
            expect(response.body.correlationId).toBeDefined();
            expect(response.body.detectionScore).toBeLessThan(30);

            // Verify logging calls
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"DETECTION_START"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"LEGITIMATE_REQUEST_PROCESSED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining(response.body.correlationId)
            );

            // Verify analytics updated
            const analytics = getDetectionLogger().getAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(0);
        });
    });

    describe('suspicious request logging', () => {
        test('should log suspicious request with detailed reasoning', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.25.1')
                .expect(200);

            // Verify response includes detection headers
            expect(response.headers['x-detection-score']).toBeDefined();
            expect(response.headers['x-correlation-id']).toBeDefined();
            expect(response.body.correlationId).toBeDefined();

            // Verify suspicious request logging
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"SUSPICIOUS_REQUEST_DETECTED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"warn"')
            );

            // Check for threat action logging
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"THREAT_ACTION_RATE_LIMITED"')
            );

            // Verify analytics updated
            const analytics = getDetectionLogger().getAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(1);
        });
    });

    describe('high-risk request logging', () => {
        test('should log high-risk request and block action', async () => {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (compatible; selenium)')
                .expect(200); // Will get faulty response but still 200

            // Verify high-risk logging
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"SUSPICIOUS_REQUEST_DETECTED"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"THREAT_ACTION_BLOCKED"')
            );

            // Verify analytics updated
            const analytics = getDetectionLogger().getAnalytics();
            expect(analytics.totalRequests).toBe(1);
            expect(analytics.suspiciousRequests).toBe(1);
            expect(analytics.blockedRequests).toBe(1);
        });
    });

    describe('error logging', () => {
        test('should log detection errors gracefully', async () => {
            // Create middleware that will cause an error
            const faultyMiddleware = new EnhancedBotDetectionMiddleware({
                ...DEFAULT_DETECTION_CONFIG,
                enabled: true,
            });

            // Mock the analyzer to throw an error
            const originalAnalyze = (faultyMiddleware as any).httpAnalyzer.analyze;
            (faultyMiddleware as any).httpAnalyzer.analyze = jest.fn(() => {
                throw new Error('Test analysis error');
            });

            const faultyApp = express();
            faultyApp.use(faultyMiddleware.middleware);
            faultyApp.get('/test', (req, res) => {
                res.json({ success: true, error: req.detectionError });
            });

            const response = await request(faultyApp)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0')
                .expect(200);

            // Verify error was logged
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"event":"DETECTION_ERROR"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('"level":"error"')
            );
            expect(mockWriteStream.write).toHaveBeenCalledWith(
                expect.stringContaining('Test analysis error')
            );

            // Verify request continued processing
            expect(response.body.success).toBe(true);
            expect(response.body.error).toBe('Test analysis error');
        });
    });

    describe('performance metrics logging', () => {
        test('should collect and log performance metrics', async () => {
            // Make multiple requests to generate metrics
            await Promise.all([
                request(app).get('/test').set('User-Agent', 'Mozilla/5.0'),
                request(app).get('/test').set('User-Agent', 'Chrome/91.0'),
                request(app).get('/test').set('User-Agent', 'Safari/14.0'),
            ]);

            // Get real-time metrics
            const metrics = getMetricsCollector().getRealTimeMetrics();
            expect(metrics.requestsPerSecond).toBeGreaterThan(0);
            expect(metrics.averageResponseTime).toBeGreaterThan(0);
            expect(metrics.memoryUsage).toBeDefined();

            // Get analytics
            const analytics = getDetectionLogger().getAnalytics();
            expect(analytics.totalRequests).toBe(3);
            expect(analytics.averageProcessingTime).toBeGreaterThan(0);
        });
    });

    describe('correlation ID tracking', () => {
        test('should maintain correlation ID throughout request lifecycle', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0')
                .expect(200);

            const correlationId = response.body.correlationId;
            expect(correlationId).toBeDefined();

            // Verify all log entries contain the same correlation ID
            const logCalls = mockWriteStream.write.mock.calls;
            const logEntries = logCalls.map(call => JSON.parse(call[0]));

            logEntries.forEach(entry => {
                expect(entry.correlationId).toBe(correlationId);
            });

            // Verify response header matches
            expect(response.headers['x-correlation-id']).toBe(correlationId);
        });
    });

    describe('structured logging format', () => {
        test('should produce valid JSON log entries', async () => {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0')
                .expect(200);

            const logCalls = mockWriteStream.write.mock.calls;

            logCalls.forEach(call => {
                const logLine = call[0];
                expect(() => JSON.parse(logLine)).not.toThrow();

                const logEntry = JSON.parse(logLine);
                expect(logEntry).toMatchObject({
                    correlationId: expect.any(String),
                    requestId: expect.any(String),
                    timestamp: expect.any(Number),
                    level: expect.stringMatching(/^(info|warn|error)$/),
                    event: expect.any(String),
                    ip: expect.any(String),
                    userAgent: expect.any(String),
                    path: expect.any(String),
                    method: expect.any(String),
                });
            });
        });
    });

    describe('sensitive data sanitization', () => {
        test('should sanitize sensitive headers in logs', async () => {
            await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0')
                .set('Authorization', 'Bearer secret-token')
                .set('Cookie', 'session=secret-session')
                .set('X-API-Key', 'api-key-123')
                .expect(200);

            const logCalls = mockWriteStream.write.mock.calls;
            const startLogEntry = JSON.parse(logCalls[0][0]);

            expect(startLogEntry.metadata.headers.authorization).toBe('[REDACTED]');
            expect(startLogEntry.metadata.headers.cookie).toBe('[REDACTED]');
            expect(startLogEntry.metadata.headers['x-api-key']).toBe('[REDACTED]');
            expect(startLogEntry.metadata.headers['user-agent']).toBe('Mozilla/5.0');
        });
    });

    describe('threat summary tracking', () => {
        test('should track repeat offenders in threat summaries', async () => {
            const ip = '192.168.1.100';

            // Make multiple suspicious requests from same IP
            await Promise.all([
                request(app).get('/test').set('User-Agent', 'python-requests/2.25.1').set('X-Forwarded-For', ip),
                request(app).get('/test').set('User-Agent', 'curl/7.68.0').set('X-Forwarded-For', ip),
                request(app).get('/test').set('User-Agent', 'wget/1.20.3').set('X-Forwarded-For', ip),
            ]);

            const analytics = getDetectionLogger().getAnalytics();
            const threat = analytics.topThreats.find(t => t.ip === ip);

            if (threat) {
                expect(threat.totalRequests).toBe(3);
                expect(threat.averageScore).toBeGreaterThan(0);
                expect(threat.threatTypes).toContain('fingerprint');
            }
        });
    });
});