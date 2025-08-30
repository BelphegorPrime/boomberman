import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { Request } from 'express';
import { BehaviorAnalyzer } from '../../src/detection/analyzers/BehaviorAnalyzer.js';
import { OptimizedBehaviorAnalyzer } from '../../src/detection/analyzers/OptimizedBehaviorAnalyzer.js';
import { GeoAnalyzer } from '../../src/detection/analyzers/GeoAnalyzer.js';
import { OptimizedGeoAnalyzer } from '../../src/detection/analyzers/OptimizedGeoAnalyzer.js';
import { HTTPFingerprintAnalyzer } from '../../src/detection/analyzers/HTTPFingerprintAnalyzer.js';
import { OptimizedHTTPFingerprintAnalyzer } from '../../src/detection/analyzers/OptimizedHTTPFingerprintAnalyzer.js';
import { CacheManager } from '../../src/detection/cache/CacheManager.js';
import { PerformanceMonitor } from '../../src/detection/performance/PerformanceMonitor.js';

describe('Analyzer Performance Tests', () => {
    let performanceMonitor: PerformanceMonitor;
    let cacheManager: CacheManager;
    let mockRequest: Partial<Request>;

    beforeEach(() => {
        performanceMonitor = new PerformanceMonitor();
        cacheManager = new CacheManager();

        mockRequest = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br',
                'connection': 'keep-alive',
                'cache-control': 'max-age=0',
                'upgrade-insecure-requests': '1',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none'
            },
            rawHeaders: [
                'Host', 'example.com',
                'Connection', 'keep-alive',
                'Cache-Control', 'max-age=0',
                'User-Agent', 'Mozilla/5.0...',
                'Accept', 'text/html,application/xhtml+xml...'
            ],
            path: '/test',
            method: 'GET',
            get: (header: string) => mockRequest.headers?.[header.toLowerCase()]
        } as Request;
    });

    afterEach(() => {
        cacheManager.shutdown();
    });

    test('Behavior Analyzer performance comparison', async () => {
        const originalAnalyzer = new BehaviorAnalyzer();
        const optimizedAnalyzer = new OptimizedBehaviorAnalyzer(cacheManager);
        const ip = '192.168.1.1';

        // Warm up both analyzers
        for (let i = 0; i < 10; i++) {
            originalAnalyzer.analyze(ip, mockRequest as Request);
            optimizedAnalyzer.analyze(ip, mockRequest as Request);
        }

        const result = await performanceMonitor.benchmark(
            'behavior-analysis',
            () => originalAnalyzer.analyze(ip, mockRequest as Request),
            () => optimizedAnalyzer.analyze(ip, mockRequest as Request),
            1000
        );

        expect(result.improvement.avgSpeedup).toBeGreaterThan(1.2); // At least 20% improvement
        expect(result.optimized.avg).toBeLessThan(10); // Should be under 10ms

        console.log(`Behavior Analysis Speedup: ${result.improvement.avgSpeedup.toFixed(2)}x`);
    });

    test('Geo Analyzer performance comparison', async () => {
        const originalAnalyzer = new GeoAnalyzer();
        const optimizedAnalyzer = new OptimizedGeoAnalyzer(cacheManager);

        // Initialize both analyzers
        await originalAnalyzer.initialize();
        await optimizedAnalyzer.initialize();

        const testIPs = [
            '8.8.8.8',
            '1.1.1.1',
            '208.67.222.222',
            '9.9.9.9',
            '76.76.19.19'
        ];

        // Warm up caches
        for (const ip of testIPs) {
            await originalAnalyzer.analyze(ip);
            await optimizedAnalyzer.analyze(ip);
        }

        const result = await performanceMonitor.benchmark(
            'geo-analysis',
            () => originalAnalyzer.analyze(testIPs[Math.floor(Math.random() * testIPs.length)]),
            () => optimizedAnalyzer.analyze(testIPs[Math.floor(Math.random() * testIPs.length)]),
            500
        );

        expect(result.improvement.avgSpeedup).toBeGreaterThan(2.0); // Should be significantly faster with caching
        expect(result.optimized.avg).toBeLessThan(5); // Should be very fast with cache hits

        console.log(`Geo Analysis Speedup: ${result.improvement.avgSpeedup.toFixed(2)}x`);
    });

    test('HTTP Fingerprint Analyzer performance comparison', async () => {
        const originalAnalyzer = new HTTPFingerprintAnalyzer();
        const optimizedAnalyzer = new OptimizedHTTPFingerprintAnalyzer(cacheManager);

        // Warm up
        for (let i = 0; i < 10; i++) {
            originalAnalyzer.analyze(mockRequest as Request);
            optimizedAnalyzer.analyze(mockRequest as Request);
        }

        const result = await performanceMonitor.benchmark(
            'fingerprint-analysis',
            () => originalAnalyzer.analyze(mockRequest as Request),
            () => optimizedAnalyzer.analyze(mockRequest as Request),
            2000
        );

        expect(result.improvement.avgSpeedup).toBeGreaterThan(1.5); // At least 50% improvement
        expect(result.optimized.avg).toBeLessThan(5); // Should be very fast

        console.log(`Fingerprint Analysis Speedup: ${result.improvement.avgSpeedup.toFixed(2)}x`);
    });

    test('Memory usage optimization', async () => {
        const originalAnalyzer = new BehaviorAnalyzer();
        const optimizedAnalyzer = new OptimizedBehaviorAnalyzer(cacheManager, {
            minHumanInterval: 500,
            maxConsistency: 0.8,
            sessionTimeout: 30 * 60 * 1000,
            maxRequestHistory: 25, // Reduced from default 50
            enableOptimizations: true
        });

        // Simulate heavy usage
        const ips = Array.from({ length: 1000 }, (_, i) => `192.168.${Math.floor(i / 255)}.${i % 255}`);

        for (let round = 0; round < 10; round++) {
            for (const ip of ips) {
                originalAnalyzer.analyze(ip, mockRequest as Request);
                optimizedAnalyzer.analyze(ip, mockRequest as Request);
            }
        }

        // Check session counts
        const originalSessionCount = originalAnalyzer.getActiveSessionCount();
        const optimizedSessionCount = cacheManager.getStats().sessions.size;

        // Optimized version should use cache manager and potentially have fewer sessions
        // due to TTL-based cleanup
        expect(optimizedSessionCount).toBeLessThanOrEqual(originalSessionCount);

        console.log(`Original sessions: ${originalSessionCount}, Optimized sessions: ${optimizedSessionCount}`);
    });

    test('Batch processing performance', async () => {
        const optimizedAnalyzer = new OptimizedHTTPFingerprintAnalyzer(cacheManager);
        const requests = Array.from({ length: 100 }, () => mockRequest as Request);

        const timer = performanceMonitor.startTiming('batch-fingerprint-analysis');
        const results = optimizedAnalyzer.batchAnalyze(requests);
        const duration = timer.end();

        expect(results).toHaveLength(100);
        expect(duration).toBeLessThan(50); // Batch processing should be efficient
        expect(results.every(r => r.headerSignature)).toBe(true);
    });

    test('Cache warming performance', async () => {
        const optimizedAnalyzer = new OptimizedHTTPFingerprintAnalyzer(cacheManager);

        const timer = performanceMonitor.startTiming('cache-warmup');
        optimizedAnalyzer.warmupCaches();
        const duration = timer.end();

        expect(duration).toBeLessThan(10); // Cache warming should be very fast

        const stats = optimizedAnalyzer.getPerformanceStats();
        expect(stats.signatureCacheSize).toBeGreaterThan(0);
    });

    test('Performance under concurrent load', async () => {
        const optimizedBehaviorAnalyzer = new OptimizedBehaviorAnalyzer(cacheManager);
        const optimizedGeoAnalyzer = new OptimizedGeoAnalyzer(cacheManager);
        const optimizedFingerprintAnalyzer = new OptimizedHTTPFingerprintAnalyzer(cacheManager);

        await optimizedGeoAnalyzer.initialize();

        const concurrentRequests = 500;
        const promises: Promise<void>[] = [];

        const timer = performanceMonitor.startTiming('concurrent-analysis');

        for (let i = 0; i < concurrentRequests; i++) {
            const ip = `10.0.${Math.floor(i / 255)}.${i % 255}`;

            promises.push(
                Promise.resolve().then(async () => {
                    // Simulate concurrent analysis
                    optimizedBehaviorAnalyzer.analyze(ip, mockRequest as Request);
                    optimizedFingerprintAnalyzer.analyze(mockRequest as Request);
                    await optimizedGeoAnalyzer.analyze(ip);
                })
            );
        }

        await Promise.all(promises);
        const duration = timer.end();

        expect(duration).toBeLessThan(1000); // Should handle concurrent load well

        const cacheStats = cacheManager.getStats();
        expect(cacheStats.sessions.size).toBeGreaterThan(0);
        expect(cacheStats.geo.size).toBeGreaterThan(0);
    });

    test('Performance degradation with large session history', async () => {
        const optimizedAnalyzer = new OptimizedBehaviorAnalyzer(cacheManager);
        const ip = '192.168.1.100';

        // Build up large session history
        const timer1 = performanceMonitor.startTiming('analysis-small-history');
        for (let i = 0; i < 10; i++) {
            optimizedAnalyzer.analyze(ip, mockRequest as Request);
        }
        const duration1 = timer1.end();

        // Continue building history
        const timer2 = performanceMonitor.startTiming('analysis-large-history');
        for (let i = 0; i < 100; i++) {
            optimizedAnalyzer.analyze(ip, mockRequest as Request);
        }
        const duration2 = timer2.end();

        // Performance should not degrade significantly with larger history
        // due to optimizations like request history limits
        const degradationRatio = duration2 / duration1;
        expect(degradationRatio).toBeLessThan(3); // Should not be more than 3x slower
    });

    test('Cache hit ratio improvement over time', async () => {
        const optimizedGeoAnalyzer = new OptimizedGeoAnalyzer(cacheManager);
        await optimizedGeoAnalyzer.initialize();

        const testIPs = ['8.8.8.8', '1.1.1.1', '208.67.222.222'];

        // First round - mostly cache misses
        for (let i = 0; i < 100; i++) {
            const ip = testIPs[i % testIPs.length];
            await optimizedGeoAnalyzer.analyze(ip);
        }

        const stats1 = cacheManager.getStats();
        const hitRate1 = stats1.geo.hitRate;

        // Second round - should have more cache hits
        for (let i = 0; i < 100; i++) {
            const ip = testIPs[i % testIPs.length];
            await optimizedGeoAnalyzer.analyze(ip);
        }

        const stats2 = cacheManager.getStats();
        const hitRate2 = stats2.geo.hitRate;

        expect(hitRate2).toBeGreaterThan(hitRate1);
        expect(hitRate2).toBeGreaterThan(0.5); // Should have good hit rate

        console.log(`Cache hit rate improved from ${(hitRate1 * 100).toFixed(1)}% to ${(hitRate2 * 100).toFixed(1)}%`);
    });

    test('Performance monitoring overhead', async () => {
        const optimizedAnalyzer = new OptimizedBehaviorAnalyzer(cacheManager);
        const iterations = 1000;
        const ip = '192.168.1.1';

        // Test without monitoring
        const start1 = performance.now();
        for (let i = 0; i < iterations; i++) {
            optimizedAnalyzer.analyze(ip, mockRequest as Request);
        }
        const duration1 = performance.now() - start1;

        // Test with monitoring
        const start2 = performance.now();
        for (let i = 0; i < iterations; i++) {
            const timer = performanceMonitor.startTiming('test-analysis');
            optimizedAnalyzer.analyze(ip, mockRequest as Request);
            timer.end();
        }
        const duration2 = performance.now() - start2;

        const overhead = (duration2 - duration1) / duration1;
        expect(overhead).toBeLessThan(0.3); // Monitoring overhead should be minimal

        console.log(`Performance monitoring overhead: ${(overhead * 100).toFixed(1)}%`);
    });
});