import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { LRUCache } from '../../src/detection/cache/LRUCache.js';
import { CacheManager } from '../../src/detection/cache/CacheManager.js';
import { PerformanceMonitor } from '../../src/detection/performance/PerformanceMonitor.js';
import { SessionData } from '../../src/detection/types/SessionData.js';
import { GeoLocation } from '../../src/detection/types/GeoLocation.js';

describe('Cache Performance Tests', () => {
    let performanceMonitor: PerformanceMonitor;
    let cacheManager: CacheManager;

    beforeEach(() => {
        performanceMonitor = new PerformanceMonitor();
        cacheManager = new CacheManager({
            maxSessionEntries: 10000,
            maxGeoEntries: 50000,
            maxFingerprintEntries: 25000,
            sessionTimeout: 30 * 60 * 1000,
            geoTTL: 24 * 60 * 60 * 1000,
            fingerprintTTL: 60 * 60 * 1000,
            cleanupInterval: 5 * 60 * 1000
        });
    });

    afterEach(() => {
        cacheManager.shutdown();
    });

    test('LRU Cache performance under load', async () => {
        const cache = new LRUCache<string, string>(1000);
        const iterations = 10000;

        const timer = performanceMonitor.startTiming('lru-cache-operations');

        // Test mixed read/write operations
        for (let i = 0; i < iterations; i++) {
            const key = `key-${i % 500}`; // Create some cache hits
            const value = `value-${i}`;

            if (i % 3 === 0) {
                cache.set(key, value);
            } else {
                cache.get(key);
            }
        }

        const duration = timer.end();

        expect(duration).toBeLessThan(100); // Should complete in under 100ms
        expect(cache.getSize()).toBeLessThanOrEqual(1000);

        const stats = cache.getStats();
        expect(stats.utilizationRatio).toBeGreaterThan(0);
    });

    test('Cache Manager session operations performance', async () => {
        const iterations = 5000;
        const sessionData: SessionData = {
            ip: '192.168.1.1',
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            requestCount: 1,
            requests: [],
            fingerprints: new Set(),
            suspicionHistory: []
        };

        const timer = performanceMonitor.startTiming('cache-manager-sessions');

        for (let i = 0; i < iterations; i++) {
            const ip = `192.168.1.${i % 255}`;

            // Mix of operations
            if (i % 4 === 0) {
                cacheManager.setSession(ip, { ...sessionData, ip });
            } else {
                cacheManager.getSession(ip);
            }
        }

        const duration = timer.end();

        expect(duration).toBeLessThan(50); // Should be very fast

        const stats = cacheManager.getStats();
        expect(stats.sessions.size).toBeGreaterThan(0);
    });

    test('Cache Manager geo operations performance', async () => {
        const iterations = 10000;
        const geoData: GeoLocation = {
            country: 'US',
            region: 'California',
            city: 'San Francisco',
            isVPN: false,
            isProxy: false,
            isHosting: false,
            isTor: false,
            riskScore: 10,
            asn: 13335,
            organization: 'Cloudflare Inc'
        };

        const timer = performanceMonitor.startTiming('cache-manager-geo');

        for (let i = 0; i < iterations; i++) {
            const ip = `10.0.${Math.floor(i / 255)}.${i % 255}`;

            if (i % 3 === 0) {
                cacheManager.setGeoLocation(ip, { ...geoData });
            } else {
                cacheManager.getGeoLocation(ip);
            }
        }

        const duration = timer.end();

        expect(duration).toBeLessThan(100);

        const stats = cacheManager.getStats();
        expect(stats.geo.size).toBeGreaterThan(0);
    });

    test('Cache cleanup performance', async () => {
        // Fill cache with data
        for (let i = 0; i < 1000; i++) {
            const ip = `192.168.${Math.floor(i / 255)}.${i % 255}`;
            cacheManager.setSession(ip, {
                ip,
                firstSeen: Date.now() - (60 * 60 * 1000), // 1 hour ago
                lastSeen: Date.now() - (60 * 60 * 1000),
                requestCount: 1,
                requests: [],
                fingerprints: new Set(),
                suspicionHistory: []
            });
        }

        const timer = performanceMonitor.startTiming('cache-cleanup');
        cacheManager.cleanup();
        const duration = timer.end();

        expect(duration).toBeLessThan(50); // Cleanup should be fast
    });

    test('Memory usage estimation accuracy', () => {
        // Add known data sizes
        const sessionData: SessionData = {
            ip: '192.168.1.1',
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            requestCount: 10,
            requests: Array(10).fill({
                timestamp: Date.now(),
                path: '/test',
                method: 'GET',
                userAgent: 'Mozilla/5.0...',
                headers: { 'user-agent': 'Mozilla/5.0...' },
                responseTime: 100
            }),
            fingerprints: new Set(['fingerprint1', 'fingerprint2']),
            suspicionHistory: [0.1, 0.2, 0.3]
        };

        for (let i = 0; i < 100; i++) {
            cacheManager.setSession(`ip-${i}`, sessionData);
        }

        const stats = cacheManager.getStats();
        expect(stats.totalMemoryUsage).toBeGreaterThan(0);
        expect(stats.sessions.size).toBe(100);
    });

    test('Cache hit ratio calculation', async () => {
        // Warm up cache
        for (let i = 0; i < 100; i++) {
            const ip = `192.168.1.${i}`;
            cacheManager.setGeoLocation(ip, {
                country: 'US',
                region: 'CA',
                city: 'SF',
                isVPN: false,
                isProxy: false,
                isHosting: false,
                isTor: false,
                riskScore: 0,
                asn: 0,
                organization: 'test'
            });
        }

        // Generate cache hits and misses
        for (let i = 0; i < 200; i++) {
            const ip = `192.168.1.${i % 150}`; // Some hits, some misses
            cacheManager.getGeoLocation(ip);
        }

        const stats = cacheManager.getStats();
        expect(stats.geo.hitRate).toBeGreaterThan(0);
        expect(stats.geo.missRate).toBeGreaterThan(0);
        expect(stats.geo.hitRate + stats.geo.missRate).toBeCloseTo(1, 2);
    });

    test('Concurrent cache operations', async () => {
        const concurrentOperations = 1000;
        const promises: Promise<void>[] = [];

        const timer = performanceMonitor.startTiming('concurrent-cache-ops');

        for (let i = 0; i < concurrentOperations; i++) {
            promises.push(
                Promise.resolve().then(() => {
                    const ip = `10.0.0.${i % 255}`;
                    if (i % 2 === 0) {
                        cacheManager.setSession(ip, {
                            ip,
                            firstSeen: Date.now(),
                            lastSeen: Date.now(),
                            requestCount: 1,
                            requests: [],
                            fingerprints: new Set(),
                            suspicionHistory: []
                        });
                    } else {
                        cacheManager.getSession(ip);
                    }
                })
            );
        }

        await Promise.all(promises);
        const duration = timer.end();

        expect(duration).toBeLessThan(200); // Should handle concurrent ops well

        const stats = cacheManager.getStats();
        expect(stats.sessions.size).toBeGreaterThan(0);
    });

    test('Cache performance under memory pressure', async () => {
        const smallCache = new CacheManager({
            maxSessionEntries: 100, // Small cache to force evictions
            maxGeoEntries: 100,
            maxFingerprintEntries: 100,
            sessionTimeout: 30 * 60 * 1000,
            geoTTL: 24 * 60 * 60 * 1000,
            fingerprintTTL: 60 * 60 * 1000,
            cleanupInterval: 5 * 60 * 1000
        });

        const timer = performanceMonitor.startTiming('memory-pressure-test');

        // Add more items than cache can hold
        for (let i = 0; i < 500; i++) {
            const ip = `192.168.${Math.floor(i / 255)}.${i % 255}`;
            smallCache.setSession(ip, {
                ip,
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                requestCount: 1,
                requests: [],
                fingerprints: new Set(),
                suspicionHistory: []
            });
        }

        const duration = timer.end();

        expect(duration).toBeLessThan(100);

        const stats = smallCache.getStats();
        expect(stats.sessions.size).toBeLessThanOrEqual(100); // Should respect max size

        smallCache.shutdown();
    });

    test('Performance metrics collection overhead', async () => {
        const iterations = 10000;

        // Test without performance monitoring
        const startWithout = performance.now();
        for (let i = 0; i < iterations; i++) {
            cacheManager.getSession(`ip-${i}`);
        }
        const durationWithout = performance.now() - startWithout;

        // Test with performance monitoring
        const startWith = performance.now();
        for (let i = 0; i < iterations; i++) {
            const timer = performanceMonitor.startTiming('test-operation');
            cacheManager.getSession(`ip-${i}`);
            timer.end();
        }
        const durationWith = performance.now() - startWith;

        // Monitoring overhead should be minimal (less than 50% increase)
        const overhead = (durationWith - durationWithout) / durationWithout;
        expect(overhead).toBeLessThan(0.5);
    });
});