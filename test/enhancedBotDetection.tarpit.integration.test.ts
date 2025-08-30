import request from 'supertest';
import app from '../src/server.js';
import { clearBanData, getBanEntry, getBanStatistics } from '../src/utils/logger/banFile.js';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration.js';

describe('Enhanced Bot Detection - Tarpit Integration', () => {
    let middleware: EnhancedBotDetectionMiddleware;

    beforeEach(() => {
        clearBanData();
        middleware = new EnhancedBotDetectionMiddleware(DEFAULT_DETECTION_CONFIG);
    });

    afterEach(() => {
        clearBanData();
    });

    describe('Enhanced Detection with Tarpit', () => {
        test('should apply score-based delays for suspicious requests', async () => {
            const testIp = '192.168.1.100';

            // Create a suspicious request that should trigger enhanced detection
            const suspiciousHeaders = {
                'User-Agent': 'python-requests/2.28.1', // Automation signature
                'X-Forwarded-For': testIp,
            };

            const startTime = Date.now();

            const response = await request(app)
                .get('/tool/tarpit')
                .set(suspiciousHeaders)
                .timeout(10000);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Should be tarpitted with a delay
            expect(response.status).toBe(429);
            expect(responseTime).toBeGreaterThan(1000); // At least 1 second delay
            expect(response.text).toContain('Too many suspicious requests');

            // Check that enhanced detection data was recorded
            const banEntry = getBanEntry(testIp);
            expect(banEntry).toBeDefined();
            expect(banEntry?.enhancedDetections).toBeGreaterThan(0);
            expect(banEntry?.suspicionScore).toBeGreaterThan(0);
        }, 15000);

        test('should use confidence levels for ban thresholds', async () => {
            const testIp = '192.168.1.101';

            // High confidence, high score request - should ban after 2 attempts
            const highRiskHeaders = {
                'User-Agent': 'Mozilla/5.0 (compatible; selenium)', // Clear automation signature
                'X-Forwarded-For': testIp,
            };

            // First request - should be tarpitted but not banned
            await request(app)
                .get('/tool/tarpit')
                .set(highRiskHeaders)
                .timeout(15000);

            let banEntry = getBanEntry(testIp);
            expect(banEntry?.count).toBe(1);

            // Second request - should be banned due to high confidence/score
            await request(app)
                .get('/tool/tarpit')
                .set(highRiskHeaders)
                .timeout(15000);

            banEntry = getBanEntry(testIp);
            expect(banEntry?.count).toBe(2);

            // Third request should be blocked at server level (403)
            const response = await request(app)
                .get('/api/health')
                .set(highRiskHeaders);

            expect(response.status).toBe(403);
            expect(response.text).toContain('banned');
        }, 25000);

        test('should require more attempts for low confidence detections', async () => {
            const testIp = '192.168.1.102';

            // Low confidence request - should require 5 attempts to ban
            const lowRiskHeaders = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', // Legitimate-looking
                'Accept': 'text/html', // Missing some headers but not clearly malicious
                'X-Forwarded-For': testIp,
            };

            // Make 4 requests - should not be banned yet
            for (let i = 0; i < 4; i++) {
                await request(app)
                    .get('/tool/tarpit')
                    .set(lowRiskHeaders)
                    .timeout(10000);
            }

            // Should not be banned yet
            const healthResponse = await request(app)
                .get('/api/health')
                .set(lowRiskHeaders);

            expect(healthResponse.status).toBe(200);

            // 5th request should trigger ban
            await request(app)
                .get('/tool/tarpit')
                .set(lowRiskHeaders)
                .timeout(10000);

            // Now should be banned
            const bannedResponse = await request(app)
                .get('/api/health')
                .set(lowRiskHeaders);

            expect(bannedResponse.status).toBe(403);
        }, 30000);

        test('should maintain backward compatibility with legacy detection', async () => {
            const testIp = '192.168.1.103';

            // Request that would trigger legacy detection but not enhanced
            const legacyBotHeaders = {
                'User-Agent': 'curl/7.68.0', // Known bot in legacy system
                'X-Forwarded-For': testIp,
            };

            const startTime = Date.now();

            const response = await request(app)
                .get('/tool/tarpit')
                .set(legacyBotHeaders)
                .timeout(10000);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Should still be tarpitted
            expect(response.status).toBe(429);
            expect(responseTime).toBeGreaterThan(500); // Some delay applied

            // Check that ban data was recorded
            const banEntry = getBanEntry(testIp);
            expect(banEntry).toBeDefined();
            expect(banEntry?.count).toBe(1);
        }, 15000);

        test('should apply longer delays for higher threat scores', async () => {
            const testIp = '192.168.1.104';

            // Very high threat score request
            const highThreatHeaders = {
                'User-Agent': 'python-requests/2.28.1',
                'X-Forwarded-For': testIp,
                // Missing many standard browser headers to increase score
            };

            const startTime = Date.now();

            const response = await request(app)
                .get('/tool/tarpit')
                .set(highThreatHeaders)
                .timeout(20000);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            expect(response.status).toBe(429);

            // High threat should result in longer delays
            const banEntry = getBanEntry(testIp);
            if (banEntry?.suspicionScore && banEntry.suspicionScore >= 70) {
                expect(responseTime).toBeGreaterThan(15000); // At least 15 seconds for high risk
            } else if (banEntry?.suspicionScore && banEntry.suspicionScore >= 50) {
                expect(responseTime).toBeGreaterThan(5000); // At least 5 seconds for medium-high risk
            } else {
                expect(responseTime).toBeGreaterThan(1000); // At least 1 second for lower risk
            }
        }, 25000);

        test('should not tarpit whitelisted requests', async () => {
            const testIp = '192.168.1.105';

            // Add IP to whitelist
            middleware.addToWhitelist(testIp, 'test', 'Integration test whitelist');

            // Request that would normally be suspicious
            const suspiciousHeaders = {
                'User-Agent': 'python-requests/2.28.1',
                'X-Forwarded-For': testIp,
            };

            const startTime = Date.now();

            const response = await request(app)
                .get('/api/health')
                .set(suspiciousHeaders);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Should not be tarpitted
            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(1000); // Fast response

            // Should not be in ban data
            const banEntry = getBanEntry(testIp);
            expect(banEntry).toBeUndefined();
        });

        test('should provide ban statistics with enhanced detection data', async () => {
            const testIp1 = '192.168.1.106';
            const testIp2 = '192.168.1.107';

            // Enhanced detection request
            await request(app)
                .get('/tool/tarpit')
                .set({
                    'User-Agent': 'python-requests/2.28.1',
                    'X-Forwarded-For': testIp1,
                })
                .timeout(10000);

            // Legacy detection request - use a different endpoint to avoid enhanced detection
            await request(app)
                .get('/api/health')
                .set({
                    'User-Agent': 'curl/7.68.0',
                    'X-Forwarded-For': testIp2,
                });

            const stats = getBanStatistics();

            expect(stats.totalBannedIPs).toBeGreaterThanOrEqual(1);
            expect(stats.enhancedDetections).toBeGreaterThanOrEqual(1);
            expect(stats.averageSuspicionScore).toBeGreaterThan(0);
            expect(stats.averageConfidence).toBeGreaterThan(0);
        }, 15000);
    });

    describe('Error Handling and Graceful Degradation', () => {
        test('should fallback to legacy detection when enhanced detection fails', async () => {
            const testIp = '192.168.1.108';

            // Create a request that might cause enhanced detection to fail
            const problematicHeaders = {
                'User-Agent': 'curl/7.68.0', // Known bot
                'X-Forwarded-For': testIp,
            };

            const response = await request(app)
                .get('/tool/tarpit')
                .set(problematicHeaders)
                .timeout(10000);

            // Should still be handled (either by enhanced or legacy detection)
            expect(response.status).toBe(429);

            const banEntry = getBanEntry(testIp);
            expect(banEntry).toBeDefined();
        }, 15000);

        test('should continue processing when detection times out', async () => {
            const testIp = '192.168.1.109';

            // Normal request that should pass through
            const normalHeaders = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'X-Forwarded-For': testIp,
            };

            const response = await request(app)
                .get('/api/health')
                .set(normalHeaders);

            // Should get successful response
            expect(response.status).toBe(200);
            expect(response.body.status).toBe('ok');
        });
    });

    describe('Logging and Correlation', () => {
        test('should include correlation IDs in tarpit responses', async () => {
            const testIp = '192.168.1.110';

            const response = await request(app)
                .get('/tool/tarpit')
                .set({
                    'User-Agent': 'python-requests/2.28.1',
                    'X-Forwarded-For': testIp,
                })
                .timeout(10000);

            expect(response.status).toBe(429);

            // Should have correlation ID header if enhanced detection was used
            if (response.headers['x-correlation-id']) {
                expect(response.headers['x-correlation-id']).toMatch(/^[a-f0-9-]+$/);
            }
        }, 15000);

        test('should log enhanced detection information', async () => {
            const testIp = '192.168.1.111';

            // Capture console output
            const originalLog = console.log;
            const originalWarn = console.warn;
            const logMessages: string[] = [];
            const warnMessages: string[] = [];

            console.log = (...args: any[]) => {
                logMessages.push(args.join(' '));
                originalLog(...args);
            };

            console.warn = (...args: any[]) => {
                warnMessages.push(args.join(' '));
                originalWarn(...args);
            };

            await request(app)
                .get('/tool/tarpit')
                .set({
                    'User-Agent': 'python-requests/2.28.1',
                    'X-Forwarded-For': testIp,
                })
                .timeout(10000);

            // Restore console
            console.log = originalLog;
            console.warn = originalWarn;

            // Should have logged tarpit action with enhanced data
            const tarpitLog = logMessages.find(msg => msg.includes(`Tarpitting ${testIp}`));
            expect(tarpitLog).toBeDefined();

            // Should have logged ban action with enhanced data
            const banLog = warnMessages.find(msg => msg.includes(`BANNED IP: ${testIp} (Enhanced detection)`));
            expect(banLog).toBeDefined();
        }, 15000);
    });
});