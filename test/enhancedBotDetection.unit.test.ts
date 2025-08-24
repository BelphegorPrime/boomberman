import request from 'supertest';
import express from 'express';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import type { DetectionConfig } from '../src/detection/types/index.js';

describe('Enhanced Bot Detection Unit Tests', () => {
    let app: express.Application;
    let middleware: EnhancedBotDetectionMiddleware;

    beforeEach(() => {
        app = express();

        // Add IP extraction middleware
        app.use((req, res, next) => {
            req.realIp = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
                req.socket.remoteAddress ||
                'unknown';
            next();
        });

        // Create middleware with test configuration
        const testConfig: DetectionConfig = {
            enabled: true,
            scoringWeights: {
                fingerprint: 0.5,
                behavioral: 0.3,
                geographic: 0.1, // Reduced weight since geo might fail
                reputation: 0.1,
            },
            thresholds: {
                suspicious: 30,
                highRisk: 70,
            },
            fingerprinting: {
                requiredHeaders: ['Accept', 'Accept-Language', 'Accept-Encoding'],
                suspiciousPatterns: [/python-requests/i, /curl/i, /bot/i],
                automationSignatures: [/selenium/i, /puppeteer/i, /headless/i],
            },
            behavioral: {
                minHumanInterval: 500,
                maxConsistency: 0.8,
                sessionTimeout: 30 * 60 * 1000,
            },
            geographic: {
                highRiskCountries: ['CN', 'RU'],
                vpnPenalty: 20,
                hostingPenalty: 15,
            },
            whitelist: {
                ips: ['127.0.0.1'],
                userAgents: [/GoogleBot/i],
                asns: [],
            },
        };

        middleware = new EnhancedBotDetectionMiddleware(testConfig);

        // Add enhanced detection middleware
        app.use(middleware.middleware);

        // Test routes
        app.get('/test', (req, res) => {
            res.json({
                success: true,
                detectionResult: req.detectionResult,
                detectionMetrics: req.detectionMetrics,
                detectionError: req.detectionError,
            });
        });
    });

    describe('Basic Functionality', () => {
        test('should process requests and provide detection results', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.9')
                .set('Accept-Encoding', 'gzip, deflate, br')
                .set('Connection', 'keep-alive')
                .set('Cache-Control', 'max-age=0')
                .set('X-Forwarded-For', '203.0.113.1');

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThanOrEqual(0);
            expect(response.body.detectionResult.confidence).toBeGreaterThan(0);
            expect(response.body.detectionResult.reasons).toBeDefined();
            expect(response.body.detectionResult.fingerprint).toBeDefined();
        });

        test('should handle whitelisted user agents', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            // Should not have detection result due to whitelist bypass
            expect(response.body.detectionResult).toBeUndefined();
        });

        test('should handle whitelisted IP addresses', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '127.0.0.1')
                .set('User-Agent', 'python-requests/2.28.1'); // Normally suspicious

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            // Should not have detection result due to whitelist bypass
            expect(response.body.detectionResult).toBeUndefined();
        });
    });

    describe('Detection Capabilities', () => {
        test('should detect suspicious user agents', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.28.1')
                .set('X-Forwarded-For', '192.168.1.100');

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(0);
        });

        test('should detect automation frameworks', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36')
                .set('X-Forwarded-For', '192.168.1.100');

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(30);
        });

        test('should detect missing headers', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('X-Forwarded-For', '192.168.1.100');
            // Missing Accept, Accept-Language, Accept-Encoding headers

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(0);
        });
    });

    describe('Error Handling', () => {
        test('should handle requests gracefully when errors occur', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', '')
                .set('X-Forwarded-For', '192.168.1.100');

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            // Should have either detection result or error
            expect(
                response.body.detectionResult || response.body.detectionError
            ).toBeDefined();
        });

        test('should continue processing when detection fails', async () => {
            const response = await request(app)
                .get('/test');
            // No headers set

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
        });
    });

    describe('Configuration Management', () => {
        test('should allow runtime configuration updates', () => {
            const newConfig = {
                thresholds: {
                    suspicious: 40,
                    highRisk: 80,
                },
            };

            middleware.updateConfig(newConfig);
            const updatedConfig = middleware.getConfig();

            expect(updatedConfig.thresholds.suspicious).toBe(40);
            expect(updatedConfig.thresholds.highRisk).toBe(80);
        });

        test('should provide performance statistics', () => {
            const stats = middleware.getPerformanceStats();

            expect(stats).toBeDefined();
            expect(stats.averageProcessingTime).toBeGreaterThan(0);
            expect(stats.timeoutRate).toBeGreaterThanOrEqual(0);
            expect(stats.timeoutRate).toBeLessThanOrEqual(1);
        });

        test('should handle disabled detection', async () => {
            middleware.updateConfig({ enabled: false });

            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.28.1')
                .set('X-Forwarded-For', '192.168.1.100');

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeUndefined(); // Should skip detection
        });
    });

    describe('Performance', () => {
        test('should complete analysis within reasonable time', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('X-Forwarded-For', '192.168.1.100');

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(1000); // Should be reasonably fast
        });

        test('should handle multiple concurrent requests', async () => {
            const promises = Array(5).fill(null).map(() =>
                request(app)
                    .get('/test')
                    .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    .set('X-Forwarded-For', '192.168.1.100')
            );

            const responses = await Promise.all(promises);

            // All requests should complete successfully
            responses.forEach(response => {
                expect(response.status).toBe(200);
                expect(response.body.success).toBe(true);
            });
        });
    });
});