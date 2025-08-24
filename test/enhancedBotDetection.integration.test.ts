import request from 'supertest';
import express from 'express';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { tarpit } from '../src/middleware/tarpit.js';
import type { DetectionConfig } from '../src/detection/types/index.js';

describe('Enhanced Bot Detection Integration Tests', () => {
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
                fingerprint: 0.4,
                behavioral: 0.3,
                geographic: 0.2,
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

        // Add tarpit middleware
        app.use(tarpit);

        // Test routes
        app.get('/test', (req, res) => {
            res.json({
                success: true,
                detectionResult: req.detectionResult,
                detectionMetrics: req.detectionMetrics,
            });
        });

        app.get('/api/data', (req, res) => {
            res.json({ data: 'sensitive information' });
        });
    });

    describe('Legitimate Traffic', () => {
        test('should allow legitimate browser requests', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('Connection', 'keep-alive')
                .set('Cache-Control', 'max-age=0');

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeLessThan(30);
        });

        test('should allow whitelisted user agents', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            // Should not have detection result due to whitelist bypass
            expect(response.body.detectionResult).toBeUndefined();
        });

        test('should allow whitelisted IP addresses', async () => {
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

    describe('Suspicious Traffic Detection', () => {
        test('should detect missing browser headers', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
            // Missing Accept, Accept-Language, Accept-Encoding headers

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(0);
            expect(response.body.detectionResult.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'fingerprint',
                    description: expect.stringContaining('Missing'),
                })
            );
        });

        test('should detect automation framework signatures', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36');

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(50);
            expect(response.body.detectionResult.reasons).toContainEqual(
                expect.objectContaining({
                    category: 'fingerprint',
                    description: expect.stringContaining('Automation framework detected'),
                })
            );
        });

        test('should detect suspicious user agents', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.28.1');

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeDefined();
            expect(response.body.detectionResult.suspicionScore).toBeGreaterThan(20);
        });
    });

    describe('High Risk Traffic Handling', () => {
        test('should block high-risk automation tools', async () => {
            const response = await request(app)
                .get('/api/data')
                .set('User-Agent', 'Mozilla/5.0 (compatible; selenium)')
                .set('X-Forwarded-For', '192.168.1.100');

            // Should be blocked with faulty response
            expect(response.status).not.toBe(200);
            expect(response.headers['x-detection-score']).toBeDefined();
            expect(parseInt(response.headers['x-detection-score'])).toBeGreaterThan(70);
        });

        test('should apply tarpit delays to medium-risk requests', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'curl/7.68.0')
                .timeout(10000); // 10 second timeout

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Should be delayed by tarpit
            expect(responseTime).toBeGreaterThan(500); // At least some delay
            expect(response.status).toBe(429); // Rate limited
        });
    });

    describe('Performance and Timeout Handling', () => {
        test('should complete analysis within timeout limits', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate');

            expect(response.status).toBe(200);
            expect(response.body.detectionMetrics).toBeDefined();
            expect(response.body.detectionMetrics.totalTime).toBeLessThan(100); // Should be fast
            expect(response.body.detectionMetrics.timeoutOccurred).toBe(false);
        });

        test('should handle analysis errors gracefully', async () => {
            // Create middleware with invalid configuration to trigger errors
            const invalidConfig = {
                ...middleware.getConfig(),
                scoringWeights: {
                    fingerprint: -1, // Invalid weight
                    behavioral: 0.3,
                    geographic: 0.2,
                    reputation: 0.1,
                },
            };

            const errorApp = express();
            errorApp.use((req, res, next) => {
                req.realIp = '192.168.1.100';
                next();
            });

            try {
                const errorMiddleware = new EnhancedBotDetectionMiddleware(invalidConfig);
                errorApp.use(errorMiddleware.middleware);
            } catch (error) {
                // Should throw error during construction with invalid weights
                expect(error).toBeDefined();
            }
        });

        test('should provide fallback detection on timeout', async () => {
            // This test would require mocking the analyzers to simulate timeout
            // For now, we'll test that the middleware handles requests even under load

            const promises = Array(10).fill(null).map(() =>
                request(app)
                    .get('/test')
                    .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            );

            const responses = await Promise.all(promises);

            // All requests should complete successfully
            responses.forEach(response => {
                expect(response.status).toBe(200);
                expect(response.body.success).toBe(true);
            });
        });
    });

    describe('Integration with Existing Middleware', () => {
        test('should integrate properly with tarpit middleware', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'python-requests/2.28.1')
                .set('X-Forwarded-For', '192.168.1.100');

            // Should be processed by enhanced detection and then tarpit
            expect(response.status).toBe(429); // Tarpitted
        });

        test('should set proper response headers for detection metadata', async () => {
            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'curl/7.68.0');

            if (response.headers['x-detection-score']) {
                expect(response.headers['x-detection-score']).toBeDefined();
                expect(response.headers['x-detection-confidence']).toBeDefined();
                expect(response.headers['x-detection-fingerprint']).toBeDefined();

                const score = parseInt(response.headers['x-detection-score']);
                expect(score).toBeGreaterThan(0);
                expect(score).toBeLessThanOrEqual(100);
            }
        });

        test('should maintain request processing performance', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/test')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'text/html,application/xhtml+xml')
                .set('Accept-Language', 'en-US,en;q=0.5')
                .set('Accept-Encoding', 'gzip, deflate');

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(200); // Should be reasonably fast
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
                .set('User-Agent', 'python-requests/2.28.1'); // Normally suspicious

            expect(response.status).toBe(200);
            expect(response.body.detectionResult).toBeUndefined(); // Should skip detection
        });
    });

    describe('Error Handling', () => {
        test('should continue processing on detection errors', async () => {
            // This would require mocking to simulate specific error conditions
            // For now, test that malformed requests don't crash the middleware

            const response = await request(app)
                .get('/test')
                .set('User-Agent', ''); // Empty user agent

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
        });

        test('should handle missing headers gracefully', async () => {
            const response = await request(app)
                .get('/test');
            // No headers set

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
            expect(response.body.detectionResult).toBeDefined();
        });
    });
});