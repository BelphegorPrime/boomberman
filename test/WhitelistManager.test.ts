import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import type { Request } from 'express';
import { WhitelistManager, type WhitelistConfig, type WhitelistEntry } from '../src/detection/WhitelistManager.js';
import type { GeoLocation } from '../src/detection/types/GeoLocation.js';

describe('WhitelistManager', () => {
    let whitelistManager: WhitelistManager;
    let mockRequest: Partial<Request>;

    beforeEach(() => {
        const config: Partial<WhitelistConfig> = {
            ips: ['192.168.1.1', '10.0.0.1'],
            userAgents: [/GoogleBot/i, /BingBot/i],
            asns: [15169, 8075], // Google and Microsoft ASNs
            enableMonitoringToolsBypass: true,
            maxEntries: 100,
            defaultExpirationTime: 60 * 60 * 1000, // 1 hour for testing
        };

        whitelistManager = new WhitelistManager(config);

        mockRequest = {
            headers: {
                'user-agent': 'Mozilla/5.0 (compatible; GoogleBot/2.1; +http://www.google.com/bot.html)',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
            },
            path: '/test',
            method: 'GET',
        };
    });

    afterEach(() => {
        whitelistManager.destroy();
    });

    describe('IP Whitelisting', () => {
        test('should whitelist configured IP addresses', () => {
            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '192.168.1.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(true);
            expect(result.bypassType).toBe('ip');
            expect(result.reason).toContain('192.168.1.1 is whitelisted');
            expect(result.matchedEntries.length).toBeGreaterThan(0);
        });

        test('should handle IPv6 mapped IPv4 addresses', () => {
            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '::ffff:192.168.1.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(true);
            expect(result.bypassType).toBe('ip');
        });

        test('should not whitelist non-configured IP addresses', () => {
            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '192.168.1.100',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(false);
            expect(result.bypassType).toBe('none');
        });

        test('should add and remove IP addresses dynamically', () => {
            const entryId = whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP',
                addedBy: 'test',
            });

            let result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(true);

            // Remove the entry
            const removed = whitelistManager.removeEntry(entryId, 'test');
            expect(removed).toBe(true);

            result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(false);
        });
    });

    describe('User-Agent Whitelisting', () => {
        test('should whitelist configured user-agent patterns', () => {
            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (compatible; GoogleBot/2.1; +http://www.google.com/bot.html)'
            );

            expect(result.isWhitelisted).toBe(true);
            expect(result.bypassType).toBe('userAgent');
            expect(result.reason).toContain('matches whitelist pattern');
        });

        test('should whitelist monitoring tools when enabled', () => {
            const monitoringUserAgents = [
                'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)',
                'Mozilla/5.0 (compatible; Pingdom.com_bot_version_1.4_(http://www.pingdom.com/))',
                'StatusCake_Monitoring_Service',
                'Site24x7',
                'NewRelic-SyntheticMonitoring',
                'DatadogSynthetics',
            ];

            monitoringUserAgents.forEach(userAgent => {
                const result = whitelistManager.checkWhitelist(
                    mockRequest as Request,
                    '203.0.113.1',
                    userAgent
                );

                expect(result.isWhitelisted).toBe(true);
                expect(result.bypassType).toBe('monitoring');
                expect(result.reason).toContain('monitoring tool detected');
            });
        });

        test('should not whitelist monitoring tools when disabled', () => {
            whitelistManager.updateConfig({ enableMonitoringToolsBypass: false });

            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)'
            );

            expect(result.isWhitelisted).toBe(false);
            expect(result.bypassType).toBe('none');
        });

        test('should add and remove user-agent patterns dynamically', () => {
            const entryId = whitelistManager.addEntry({
                type: 'userAgent',
                value: /TestBot/i,
                description: 'Test bot pattern',
                addedBy: 'test',
            });

            let result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (compatible; TestBot/1.0)'
            );

            expect(result.isWhitelisted).toBe(true);

            // Remove the entry
            whitelistManager.removeEntry(entryId, 'test');

            result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (compatible; TestBot/1.0)'
            );

            expect(result.isWhitelisted).toBe(false);
        });
    });

    describe('ASN Whitelisting', () => {
        test('should whitelist configured ASN numbers', () => {
            const geoData: GeoLocation = {
                country: 'US',
                region: 'CA',
                city: 'Mountain View',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 15169, // Google ASN
                organization: 'Google LLC',
            };

            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '8.8.8.8',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                geoData
            );

            expect(result.isWhitelisted).toBe(true);
            expect(result.bypassType).toBe('asn');
            expect(result.reason).toContain('ASN 15169 is whitelisted');
        });

        test('should not whitelist non-configured ASN numbers', () => {
            const geoData: GeoLocation = {
                country: 'US',
                region: 'CA',
                city: 'San Francisco',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 12345, // Non-whitelisted ASN
                organization: 'Unknown ISP',
            };

            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                geoData
            );

            expect(result.isWhitelisted).toBe(false);
            expect(result.bypassType).toBe('none');
        });
    });

    describe('Fingerprint Whitelisting', () => {
        test('should whitelist configured fingerprints', () => {
            const fingerprint = 'test-fingerprint-123';

            whitelistManager.addEntry({
                type: 'fingerprint',
                value: fingerprint,
                description: 'Test fingerprint',
                addedBy: 'test',
            });

            const result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                undefined,
                fingerprint
            );

            expect(result.isWhitelisted).toBe(true);
            expect(result.bypassType).toBe('fingerprint');
            expect(result.reason).toContain('fingerprint is whitelisted');
        });
    });

    describe('Entry Management', () => {
        test('should enforce maximum entry limits', () => {
            // Clear existing entries and set a low limit for testing
            whitelistManager.clearAll('test');
            whitelistManager.updateConfig({ maxEntries: 2 });

            // Add entries up to the limit
            whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP 1',
                addedBy: 'test',
            });

            whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.2',
                description: 'Test IP 2',
                addedBy: 'test',
            });

            // This should throw an error
            expect(() => {
                whitelistManager.addEntry({
                    type: 'ip',
                    value: '203.0.113.3',
                    description: 'Test IP 3',
                    addedBy: 'test',
                });
            }).toThrow('Maximum whitelist entries');
        });

        test('should handle entry expiration', async () => {
            const entryId = whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Temporary IP',
                addedBy: 'test',
                expirationTime: 100, // 100ms for testing
            });

            // Should be whitelisted initially
            let result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(true);

            // Wait for expiration
            await new Promise(resolve => setTimeout(resolve, 150));

            // Should no longer be whitelisted
            result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(false);
        });

        test('should update entry properties', () => {
            const entryId = whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Original description',
                addedBy: 'test',
            });

            const updated = whitelistManager.updateEntry(entryId, {
                description: 'Updated description',
                isActive: false,
            }, 'test-updater');

            expect(updated).toBe(true);

            const entries = whitelistManager.getAllEntries();
            const entry = entries.find(e => e.id === entryId);

            expect(entry?.description).toBe('Updated description');
            expect(entry?.isActive).toBe(false);
        });

        test('should get entries by type', () => {
            whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP',
                addedBy: 'test',
            });

            whitelistManager.addEntry({
                type: 'userAgent',
                value: /TestBot/i,
                description: 'Test bot',
                addedBy: 'test',
            });

            const ipEntries = whitelistManager.getEntriesByType('ip');
            const uaEntries = whitelistManager.getEntriesByType('userAgent');

            expect(ipEntries.length).toBeGreaterThan(0);
            expect(uaEntries.length).toBeGreaterThan(0);
            expect(ipEntries.every(e => e.type === 'ip')).toBe(true);
            expect(uaEntries.every(e => e.type === 'userAgent')).toBe(true);
        });
    });

    describe('Statistics and Analytics', () => {
        test('should provide accurate statistics', async () => {
            const initialStats = whitelistManager.getStatistics();

            // Add a small delay to ensure different timestamps
            await new Promise(resolve => setTimeout(resolve, 10));

            whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP',
                addedBy: 'test',
            });

            await new Promise(resolve => setTimeout(resolve, 10));

            whitelistManager.addEntry({
                type: 'userAgent',
                value: /TestBot/i,
                description: 'Test bot',
                addedBy: 'test',
                expirationTime: 100000, // Long expiration to avoid timing issues
            });

            const stats = whitelistManager.getStatistics();

            expect(stats.totalEntries).toBeGreaterThan(initialStats.totalEntries);
            expect(stats.activeEntries).toBeGreaterThan(initialStats.activeEntries);
            expect(stats.entriesByType.ip).toBeGreaterThan(0);
            expect(stats.entriesByType.userAgent).toBeGreaterThan(0);

            // Only check if we have multiple entries
            if (stats.totalEntries > 1) {
                expect(stats.newestEntry).toBeGreaterThanOrEqual(stats.oldestEntry || 0);
            }
        });
    });

    describe('Import/Export Functionality', () => {
        test('should export and import entries', () => {
            // Add some test entries
            whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP',
                addedBy: 'test',
            });

            whitelistManager.addEntry({
                type: 'userAgent',
                value: /TestBot/i,
                description: 'Test bot',
                addedBy: 'test',
            });

            // Export entries
            const exported = whitelistManager.exportEntries();
            expect(exported.length).toBeGreaterThan(0);

            // Clear all entries
            whitelistManager.clearAll('test');

            // Import entries back
            const importedCount = whitelistManager.importEntries(exported, 'test-importer');
            expect(importedCount).toBe(exported.length);

            // Verify entries are restored
            const stats = whitelistManager.getStatistics();
            expect(stats.totalEntries).toBe(exported.length);
        });
    });

    describe('Event Handling', () => {
        test('should emit events for entry operations', () => {
            const entryAddedSpy = jest.fn();
            const entryRemovedSpy = jest.fn();
            const whitelistMatchSpy = jest.fn();

            whitelistManager.on('entryAdded', entryAddedSpy);
            whitelistManager.on('entryRemoved', entryRemovedSpy);
            whitelistManager.on('whitelistMatch', whitelistMatchSpy);

            // Add entry
            const entryId = whitelistManager.addEntry({
                type: 'ip',
                value: '203.0.113.1',
                description: 'Test IP',
                addedBy: 'test',
            });

            expect(entryAddedSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: 'ip',
                    value: '203.0.113.1',
                })
            );

            // Check whitelist (should trigger match event)
            whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(whitelistMatchSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    ip: '203.0.113.1',
                    bypassType: 'ip',
                })
            );

            // Remove entry
            whitelistManager.removeEntry(entryId, 'test');

            expect(entryRemovedSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    entry: expect.objectContaining({
                        type: 'ip',
                        value: '203.0.113.1',
                    }),
                    removedBy: 'test',
                })
            );
        });
    });

    describe('Configuration Updates', () => {
        test('should update configuration and emit events', () => {
            const configUpdatedSpy = jest.fn();
            whitelistManager.on('configUpdated', configUpdatedSpy);

            const newConfig = {
                enableMonitoringToolsBypass: false,
                maxEntries: 500,
            };

            whitelistManager.updateConfig(newConfig);

            expect(configUpdatedSpy).toHaveBeenCalledWith(
                expect.objectContaining({
                    newConfig: expect.objectContaining(newConfig),
                })
            );
        });
    });

    describe('Edge Cases', () => {
        test('should handle empty or invalid inputs gracefully', () => {
            // Empty IP
            let result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            );

            expect(result.isWhitelisted).toBe(false);

            // Empty user agent
            result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                ''
            );

            expect(result.isWhitelisted).toBe(false);

            // Null geo data
            result = whitelistManager.checkWhitelist(
                mockRequest as Request,
                '203.0.113.1',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                undefined
            );

            expect(result.isWhitelisted).toBe(false);
        });

        test('should handle malformed regex patterns', () => {
            // This should not throw an error
            expect(() => {
                whitelistManager.addEntry({
                    type: 'userAgent',
                    value: 'not-a-regex-but-string',
                    description: 'String instead of regex',
                    addedBy: 'test',
                });
            }).not.toThrow();
        });
    });
});