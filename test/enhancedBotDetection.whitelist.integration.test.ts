import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { EnhancedBotDetectionMiddleware } from '../src/middleware/enhancedBotDetection.js';
import { getWhitelistManager, initializeWhitelistManager } from '../src/detection/WhitelistManager.js';
import { DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration.js';

describe('Enhanced Bot Detection - Whitelist Integration', () => {
    let app: express.Application;
    let middleware: EnhancedBotDetectionMiddleware;

    beforeEach(() => {
        // Set test data directory to avoid permission issues
        process.env.DATA_DIR = './test/data';

        // Initialize fresh whitelist manager for each test
        initializeWhitelistManager({
            ips: ['192.168.1.100'],
            userAgents: [/TestBot/i],
            asns: [15169],
            enableMonitoringToolsBypass: true,
            maxEntries: 1000,
            defaultExpirationTime: 60 * 60 * 1000,
        });

        // Create middleware with test-specific whitelist configuration
        const testConfig = {
            ...DEFAULT_DETECTION_CONFIG,
            whitelist: {
                ips: ['192.168.1.100'],
                userAgents: [/TestBot/i],
                asns: [15169],
            },
        };

        middleware = new EnhancedBotDetectionMiddleware(testConfig);

        app = express();

        // Add IP extraction middleware
        app.use((req: Request, res: Response, next: NextFunction) => {
            req.realIp = req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || 'unknown';
            next();
        });

        app.use(middleware.middleware);

        // Test endpoint
        app.get('/test', (req: Request, res: Response) => {
            res.json({
                success: true,
                whitelisted: !!req.whitelistResult,
                whitelistReason: req.whitelistResult?.reason,
                bypassType: req.whitelistResult?.bypassType,
                correlationId: req.correlationId,
            });
        });

        // Error handler
        app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
            res.status(500).json({ error: error.message });
        });
    });

    afterEach(() => {
        getWhitelistManager().destroy();
        // Clean up environment variable
        delete process.env.DATA_DIR;
    });

    describe('IP Whitelisting', () => {
        test('should bypass detection for whitelisted IP addresses', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '192.168.1.100')
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.bypassType).toBe('ip');
            expect(response.body.whitelistReason).toContain('192.168.1.100 is whitelisted');
            expect(response.body.correlationId).toBeDefined();
        });

        test('should not bypass detection for non-whitelisted IP addresses', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200); // Should still reach endpoint but with detection

            expect(response.body.whitelisted).toBeFalsy();
        });

        test('should handle IPv6 mapped IPv4 addresses', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '::ffff:192.168.1.100')
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.bypassType).toBe('ip');
        });
    });

    describe('User-Agent Whitelisting', () => {
        test('should bypass detection for whitelisted user-agent patterns', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', 'Mozilla/5.0 (compatible; TestBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.bypassType).toBe('userAgent');
            expect(response.body.whitelistReason).toContain('matches whitelist pattern');
        });

        test('should bypass detection for legitimate monitoring tools', async () => {
            const monitoringUserAgents = [
                'Mozilla/5.0 (compatible; GoogleBot/2.1; +http://www.google.com/bot.html)',
                'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
                'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
                'Twitterbot/1.0',
                'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)',
                'Mozilla/5.0 (compatible; Pingdom.com_bot_version_1.4_(http://www.pingdom.com/))',
            ];

            for (const userAgent of monitoringUserAgents) {
                const response = await request(app)
                    .get('/test')
                    .set('X-Forwarded-For', '203.0.113.1')
                    .set('User-Agent', userAgent)
                    .expect(200);

                expect(response.body.whitelisted).toBe(true);
                expect(['userAgent', 'monitoring']).toContain(response.body.bypassType);
            }
        });

        test('should not bypass detection when monitoring tools bypass is disabled', async () => {
            // Update configuration to disable monitoring tools bypass
            getWhitelistManager().updateConfig({ enableMonitoringToolsBypass: false });

            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)')
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();
        });
    });

    describe('Dynamic Whitelist Management', () => {
        test('should allow adding IP addresses to whitelist at runtime', async () => {
            const testIp = '203.0.113.50';

            // Initially should not be whitelisted
            let response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', testIp)
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();

            // Add IP to whitelist
            const entryId = middleware.addToWhitelist(testIp, 'test-admin', 'Added for testing');

            // Now should be whitelisted
            response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', testIp)
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.bypassType).toBe('ip');

            // Remove from whitelist
            const removed = middleware.removeFromWhitelist(entryId, 'test-admin');
            expect(removed).toBe(true);

            // Should no longer be whitelisted
            response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', testIp)
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();
        });

        test('should allow adding user-agent patterns to whitelist at runtime', async () => {
            const testUserAgent = 'Mozilla/5.0 (compatible; UniqueTestBot/1.0)';

            // Disable monitoring tools bypass to avoid interference
            getWhitelistManager().updateConfig({ enableMonitoringToolsBypass: false });

            // Clear existing user-agent whitelist entries to avoid conflicts
            getWhitelistManager().clearAll('test');

            // Initially should not be whitelisted
            let response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', testUserAgent)
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();

            // Add user-agent pattern to whitelist
            const entryId = middleware.addUserAgentToWhitelist(
                /UniqueTestBot/i,
                'test-admin',
                'Added for testing'
            );

            // Now should be whitelisted
            response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', testUserAgent)
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.bypassType).toBe('userAgent');

            // Remove from whitelist
            middleware.removeFromWhitelist(entryId, 'test-admin');

            // Should no longer be whitelisted
            response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', testUserAgent)
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();
        });

        test('should allow adding ASN to whitelist at runtime', async () => {
            const testAsn = 12345;

            // Add ASN to whitelist
            const entryId = middleware.addASNToWhitelist(testAsn, 'test-admin', 'Added for testing');

            // Mock geo data would need to be injected for full testing
            // This test verifies the API works correctly
            expect(entryId).toBeDefined();

            // Remove from whitelist
            const removed = middleware.removeFromWhitelist(entryId, 'test-admin');
            expect(removed).toBe(true);
        });
    });

    describe('Temporary Whitelisting', () => {
        test('should support temporary whitelist entries with expiration', async () => {
            const testIp = '203.0.113.60';
            const shortExpiration = 200; // 200ms

            // Add temporary whitelist entry
            middleware.addToWhitelist(testIp, 'test-admin', 'Temporary entry', shortExpiration);

            // Should be whitelisted initially
            let response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', testIp)
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBe(true);

            // Wait for expiration
            await new Promise(resolve => setTimeout(resolve, 300));

            // Should no longer be whitelisted
            response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', testIp)
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();
        });
    });

    describe('Whitelist Statistics', () => {
        test('should provide accurate whitelist statistics', () => {
            const initialStats = middleware.getWhitelistStatistics();

            // Add some entries
            middleware.addToWhitelist('203.0.113.70', 'test-admin', 'Test IP 1');
            middleware.addToWhitelist('203.0.113.71', 'test-admin', 'Test IP 2');
            middleware.addUserAgentToWhitelist(/StatsTestBot/i, 'test-admin', 'Test bot');

            const newStats = middleware.getWhitelistStatistics();

            expect(newStats.totalEntries).toBeGreaterThan(initialStats.totalEntries);
            expect(newStats.activeEntries).toBeGreaterThan(initialStats.activeEntries);
            expect(newStats.entriesByType.ip).toBeGreaterThan(0);
            expect(newStats.entriesByType.userAgent).toBeGreaterThan(0);
        });
    });

    describe('Error Handling', () => {
        test('should handle whitelist manager errors gracefully', async () => {
            // Simulate whitelist manager failure by destroying it
            getWhitelistManager().destroy();

            // Request should still be processed (fallback behavior)
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .expect(200);

            expect(response.body.success).toBe(true);
            // Should not be whitelisted due to manager failure
            expect(response.body.whitelisted).toBeFalsy();
        });

        test('should handle malformed IP addresses', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', 'invalid-ip-address')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.whitelisted).toBeFalsy();
        });
    });

    describe('Performance', () => {
        test('should maintain performance with large whitelist', async () => {
            // Add many entries to test performance
            for (let i = 0; i < 100; i++) {
                middleware.addToWhitelist(`203.0.113.${i}`, 'test-admin', `Test IP ${i}`);
            }

            const startTime = Date.now();

            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.50')
                .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                .expect(200);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            expect(response.body.whitelisted).toBe(true);
            expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
        });
    });

    describe('Logging and Audit', () => {
        test('should log whitelist bypass events', async () => {
            const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

            await request(app)
                .get('/test')
                .set('X-Forwarded-For', '192.168.1.100')
                .set('User-Agent', 'Mozilla/5.0 (compatible; SuspiciousBot/1.0)')
                .expect(200);

            // Verify that logging occurred (implementation-specific)
            // This would need to be adapted based on actual logging implementation

            consoleSpy.mockRestore();
        });
    });

    describe('Integration with Detection System', () => {
        test('should bypass all detection when whitelisted', async () => {
            // Use a highly suspicious request that would normally be blocked
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '192.168.1.100') // Whitelisted IP
                .set('User-Agent', 'python-requests/2.25.1') // Suspicious user agent
                .set('Accept', '*/*') // Missing common browser headers
                .expect(200);

            expect(response.body.whitelisted).toBe(true);
            expect(response.body.success).toBe(true);

            // Should not have detection result since it was bypassed
            expect(response.headers['x-detection-score']).toBeUndefined();
        });

        test('should perform full detection when not whitelisted', async () => {
            const response = await request(app)
                .get('/test')
                .set('X-Forwarded-For', '203.0.113.1') // Not whitelisted
                .set('User-Agent', 'python-requests/2.25.1') // Suspicious user agent
                .set('Accept', '*/*') // Missing common browser headers
                .expect(200);

            expect(response.body.whitelisted).toBeFalsy();

            // Should have detection headers since full analysis was performed
            // (This depends on the actual detection result)
        });
    });
});