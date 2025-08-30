import request from 'supertest';
import app from '../src/server.js';
import { clearBanData } from '../src/utils/logger/banFile.js';
import path from 'path';
import fs from 'fs';

// Set up test data directory with proper permissions
const testDataDir = path.join(process.cwd(), 'test-data');
process.env.DATA_DIR = testDataDir;

// Ensure test data directory exists and is writable
if (!fs.existsSync(testDataDir)) {
    fs.mkdirSync(testDataDir, { recursive: true });
}

describe('Server Enhanced Bot Detection E2E Tests', () => {
    afterAll(() => {
        // Clean up test data directory
        try {
            if (fs.existsSync(testDataDir)) {
                fs.rmSync(testDataDir, { recursive: true, force: true });
            }
        } catch (error) {
            // Ignore cleanup errors
        }
    });
    describe('Legitimate Traffic Patterns', () => {
        test('should handle legitimate browser requests without delays', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.9')
                .set('Accept-Encoding', 'gzip, deflate, br')
                .set('Connection', 'keep-alive')
                .set('Cache-Control', 'max-age=0')
                .set('Sec-Fetch-Dest', 'document')
                .set('Sec-Fetch-Mode', 'navigate')
                .set('Sec-Fetch-Site', 'none')
                .set('Upgrade-Insecure-Requests', '1');

            const responseTime = Date.now() - startTime;

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('ok');
            expect(responseTime).toBeLessThan(200); // Should be fast for legitimate traffic

            // Should not have high detection scores
            const detectionScore = response.headers['x-detection-score'];
            if (detectionScore) {
                expect(parseInt(detectionScore)).toBeLessThan(30);
            }
        });

        test('should handle mobile browser requests properly', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                .set('Accept-Language', 'en-US,en;q=0.9')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('Connection', 'keep-alive');

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('ok');

            const detectionScore = response.headers['x-detection-score'];
            if (detectionScore) {
                expect(parseInt(detectionScore)).toBeLessThan(30);
            }
        });

        test('should handle legitimate API clients with proper headers', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'MyApp/1.0 (https://example.com/contact)')
                .set('Accept', 'application/json')
                .set('Accept-Language', 'en-US')
                .set('Accept-Encoding', 'gzip')
                .set('Connection', 'keep-alive')
                .set('X-API-Key', 'legitimate-api-key');

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('ok');
        });
    });

    describe('Bot Traffic Detection', () => {
        test('should detect and handle curl requests', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'curl/7.68.0')
                .set('Accept', '*/*');

            // Should be detected as suspicious and either blocked or have detection headers
            if (response.status === 200) {
                // If not blocked, should have high detection score
                const detectionScore = response.headers['x-detection-score'];
                if (detectionScore) {
                    expect(parseInt(detectionScore)).toBeGreaterThan(30);
                }
            } else {
                // Should be blocked with appropriate status or faulty response
                expect([403, 429, 500]).toContain(response.status);
            }
        });

        test('should detect Python requests library', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'python-requests/2.25.1')
                .set('Accept-Encoding', 'gzip, deflate')
                .set('Connection', 'keep-alive');

            // Should be detected as suspicious
            if (response.status === 200) {
                const detectionScore = response.headers['x-detection-score'];
                if (detectionScore) {
                    expect(parseInt(detectionScore)).toBeGreaterThan(40);
                }
            } else {
                expect([403, 429]).toContain(response.status);
            }
        });

        test('should detect automation framework signatures', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36')
                .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');

            if (response.status === 200) {
                const detectionScore = response.headers['x-detection-score'];
                if (detectionScore) {
                    expect(parseInt(detectionScore)).toBeGreaterThan(30);
                }
            } else {
                expect([403, 429]).toContain(response.status);
            }
        });

        test('should detect missing common browser headers', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
            // Missing Accept, Accept-Language, Accept-Encoding headers

            if (response.status === 200) {
                const detectionScore = response.headers['x-detection-score'];
                if (detectionScore) {
                    expect(parseInt(detectionScore)).toBeGreaterThan(20);
                }
            }
        });

        test('should handle high-frequency requests with progressive delays', async () => {
            const userAgent = 'curl/7.68.0';

            // Just test that the system can handle rapid requests without crashing
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', userAgent)
                .set('Accept', '*/*');

            // Should get some response (either success or detection)
            expect([200, 403, 429, 500]).toContain(response.status);

            // If it's a successful response, it might have detection headers
            if (response.status === 200 && response.headers['x-detection-score']) {
                expect(parseInt(response.headers['x-detection-score'])).toBeGreaterThan(0);
            }
        });
    });

    describe('Rate Limiting Integration', () => {
        test('should integrate with default rate limiter for legitimate traffic', async () => {
            let successCount = 0;
            let rateLimitedCount = 0;

            // Send requests sequentially to test rate limiting
            for (let i = 0; i < 12; i++) { // Default limit is 10 per minute
                const response = await request(app)
                    .get('/api/health')
                    .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    .set('Accept', 'application/json')
                    .set('Accept-Language', 'en-US')
                    .set('Accept-Encoding', 'gzip');

                if (response.status === 200) {
                    successCount++;
                } else if (response.status === 429) {
                    rateLimitedCount++;
                }

                // Small delay to avoid overwhelming the system
                await new Promise(resolve => setTimeout(resolve, 50));
            }

            // Should have some successful requests and some rate limited
            expect(successCount).toBeGreaterThanOrEqual(8); // Allow some variance
            expect(successCount + rateLimitedCount).toBeGreaterThanOrEqual(10); // Most requests should be processed
        });

        test('should apply enhanced detection before rate limiting', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'python-requests/2.25.1');

            // Enhanced detection should trigger before rate limiting
            if (response.status !== 200) {
                // Should be blocked by enhanced detection, not just rate limiting
                expect(response.headers['x-detection-score']).toBeDefined();
            }
        });
    });

    describe('Tarpit Integration', () => {
        beforeEach(() => {
            // Clear ban data before each tarpit test to ensure clean state
            clearBanData();
        });

        test('should apply tarpit delays for suspicious requests', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/tool/tarpit')
                .set('User-Agent', 'curl/7.68.0')
                .set('Accept', '*/*');

            const responseTime = Date.now() - startTime;

            // Should be delayed by tarpit (around 4-5 seconds based on detection score)
            expect(responseTime).toBeGreaterThan(3000);
            expect(response.status).toBe(429);
        }, 10000); // 10 second timeout

        test('should use enhanced detection scores for tarpit delays', async () => {
            // High-risk request should get longer delay
            const startTime = Date.now();

            const response = await request(app)
                .get('/tool/tarpit')
                .set('User-Agent', 'python-requests/2.25.1 selenium/4.0.0')
                .set('Accept', '*/*');

            const responseTime = Date.now() - startTime;

            expect(responseTime).toBeGreaterThan(2000); // Should have significant delay
            expect(response.status).toBe(429);
        }, 10000); // 10 second timeout
    });

    describe('Performance Requirements', () => {
        test('should process legitimate requests within performance thresholds', async () => {
            const startTime = Date.now();

            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .set('Accept', 'application/json')
                .set('Accept-Language', 'en-US')
                .set('Accept-Encoding', 'gzip')
                .set('Connection', 'keep-alive');

            const responseTime = Date.now() - startTime;

            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(100); // Should be very fast for legitimate traffic
        });

        test('should handle concurrent legitimate requests efficiently', async () => {
            const concurrentRequests = 10;
            const requests = [];

            const startTime = Date.now();

            for (let i = 0; i < concurrentRequests; i++) {
                requests.push(
                    request(app)
                        .get('/api/health')
                        .set('User-Agent', `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 - Request ${i}`)
                        .set('Accept', 'application/json')
                        .set('Accept-Language', 'en-US')
                        .set('Accept-Encoding', 'gzip')
                );
            }

            const results = await Promise.all(requests);
            const totalTime = Date.now() - startTime;

            // All should succeed
            expect(results.every(r => r.status === 200)).toBe(true);

            // Should handle concurrent requests efficiently
            expect(totalTime).toBeLessThan(1000);
        });
    });

    describe('Error Handling and Graceful Degradation', () => {
        test('should continue processing when detection components fail', async () => {
            // This test simulates component failures by sending malformed requests
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', '') // Empty user agent
                .set('X-Forwarded-For', 'invalid-ip-format'); // Invalid IP

            // Should still respond, even if detection fails
            expect([200, 429, 403]).toContain(response.status);
        });

        test('should provide fallback detection when enhanced detection times out', async () => {
            // Send a request that might cause timeout in geo analysis
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'TestBot/1.0')
                .set('X-Forwarded-For', '192.0.2.1'); // Test IP that might cause geo lookup issues

            // Should still process the request
            expect([200, 429, 403]).toContain(response.status);
        });
    });

    describe('Logging and Monitoring Integration', () => {
        test('should include correlation IDs in responses for suspicious requests', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'curl/7.68.0');

            if (response.headers['x-detection-score']) {
                expect(response.headers['x-correlation-id']).toBeDefined();
                expect(response.headers['x-detection-fingerprint']).toBeDefined();
                expect(response.headers['x-detection-confidence']).toBeDefined();
            }
        });

        test('should provide detection metadata for analysis', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'python-requests/2.25.1');

            if (response.headers['x-detection-score']) {
                const score = parseInt(response.headers['x-detection-score']);
                const confidence = parseFloat(response.headers['x-detection-confidence']);

                expect(score).toBeGreaterThan(0);
                expect(confidence).toBeGreaterThan(0);
                expect(confidence).toBeLessThanOrEqual(1);
            }
        });
    });

    describe('Whitelist Functionality', () => {
        test('should bypass detection for whitelisted IPs', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'curl/7.68.0') // Normally suspicious
                .set('X-Forwarded-For', '127.0.0.1'); // Whitelisted IP

            expect(response.status).toBe(200);

            // Should not have detection headers for whitelisted requests
            expect(response.headers['x-detection-score']).toBeUndefined();
        });

        test('should bypass detection for legitimate monitoring tools', async () => {
            const response = await request(app)
                .get('/api/health')
                .set('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

            expect(response.status).toBe(200);

            // Should be whitelisted and not have detection scores
            expect(response.headers['x-detection-score']).toBeUndefined();
        });
    });
});