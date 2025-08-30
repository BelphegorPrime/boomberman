import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { Request } from 'express';
import { PerformanceMonitor } from '../../src/detection/performance/PerformanceMonitor.js';
import { CacheManager } from '../../src/detection/cache/CacheManager.js';
import { BehaviorAnalyzer } from '../../src/detection/analyzers/BehaviorAnalyzer.js';
import { OptimizedBehaviorAnalyzer } from '../../src/detection/analyzers/OptimizedBehaviorAnalyzer.js';
import { GeoAnalyzer } from '../../src/detection/analyzers/GeoAnalyzer.js';
import { OptimizedGeoAnalyzer } from '../../src/detection/analyzers/OptimizedGeoAnalyzer.js';
import { HTTPFingerprintAnalyzer } from '../../src/detection/analyzers/HTTPFingerprintAnalyzer.js';
import { OptimizedHTTPFingerprintAnalyzer } from '../../src/detection/analyzers/OptimizedHTTPFingerprintAnalyzer.js';

describe('Comprehensive Benchmark Suite', () => {
    let performanceMonitor: PerformanceMonitor;
    let cacheManager: CacheManager;
    let testRequests: Request[];
    let testIPs: string[];

    beforeAll(async () => {
        performanceMonitor = new PerformanceMonitor();
        cacheManager = new CacheManager({
            maxSessionEntries: 50000,
            maxGeoEntries: 100000,
            maxFingerprintEntries: 75000,
            sessionTimeout: 30 * 60 * 1000,
            geoTTL: 24 * 60 * 60 * 1000,
            fingerprintTTL: 60 * 60 * 1000,
            cleanupInterval: 5 * 60 * 1000
        });

        // Generate test data
        testRequests = generateTestRequests(100);
        testIPs = generateTestIPs(1000);

        console.log('Benchmark Suite initialized with test data');
    });

    afterAll(() => {
        cacheManager.shutdown();

        // Export benchmark results
        const results = performanceMonitor.exportMetrics();
        console.log('\n=== BENCHMARK RESULTS ===');
        console.log(results);
    });

    test('Full Detection Pipeline Benchmark', async () => {
        // Original pipeline
        const originalBehavior = new BehaviorAnalyzer();
        const originalGeo = new GeoAnalyzer();
        const originalFingerprint = new HTTPFingerprintAnalyzer();

        await originalGeo.initialize();

        // Optimized pipeline
        const optimizedBehavior = new OptimizedBehaviorAnalyzer(cacheManager);
        const optimizedGeo = new OptimizedGeoAnalyzer(cacheManager);
        const optimizedFingerprint = new OptimizedHTTPFingerprintAnalyzer(cacheManager);

        await optimizedGeo.initialize();

        const originalPipeline = async (ip: string, req: Request) => {
            const behaviorResult = originalBehavior.analyze(ip, req);
            const geoResult = await originalGeo.analyze(ip);
            const fingerprintResult = originalFingerprint.analyze(req);
            return { behaviorResult, geoResult, fingerprintResult };
        };

        const optimizedPipeline = async (ip: string, req: Request) => {
            const behaviorResult = optimizedBehavior.analyze(ip, req);
            const geoResult = await optimizedGeo.analyze(ip);
            const fingerprintResult = optimizedFingerprint.analyze(req);
            return { behaviorResult, geoResult, fingerprintResult };
        };

        // Warm up
        for (let i = 0; i < 10; i++) {
            const ip = testIPs[i % testIPs.length];
            const req = testRequests[i % testRequests.length];
            await originalPipeline(ip, req);
            await optimizedPipeline(ip, req);
        }

        const result = await performanceMonitor.benchmark(
            'full-detection-pipeline',
            () => {
                const ip = testIPs[Math.floor(Math.random() * testIPs.length)];
                const req = testRequests[Math.floor(Math.random() * testRequests.length)];
                return originalPipeline(ip, req);
            },
            () => {
                const ip = testIPs[Math.floor(Math.random() * testIPs.length)];
                const req = testRequests[Math.floor(Math.random() * testRequests.length)];
                return optimizedPipeline(ip, req);
            },
            200
        );

        expect(result.improvement.avgSpeedup).toBeGreaterThan(1.5);
        expect(result.optimized.avg).toBeLessThan(20); // Should complete in under 20ms

        console.log(`\nFull Pipeline Benchmark:`);
        console.log(`  Original avg: ${result.original.avg.toFixed(2)}ms`);
        console.log(`  Optimized avg: ${result.optimized.avg.toFixed(2)}ms`);
        console.log(`  Speedup: ${result.improvement.avgSpeedup.toFixed(2)}x`);
    });

    test('Memory Efficiency Benchmark', async () => {
        const optimizedBehavior = new OptimizedBehaviorAnalyzer(cacheManager, {
            minHumanInterval: 500,
            maxConsistency: 0.8,
            sessionTimeout: 30 * 60 * 1000,
            maxRequestHistory: 25,
            enableOptimizations: true
        });

        const optimizedGeo = new OptimizedGeoAnalyzer(cacheManager);
        await optimizedGeo.initialize();

        // Simulate realistic traffic patterns
        const timer = performanceMonitor.startTiming('memory-efficiency-test');

        for (let round = 0; round < 50; round++) {
            // Simulate burst of requests
            for (let i = 0; i < 100; i++) {
                const ip = testIPs[Math.floor(Math.random() * testIPs.length)];
                const req = testRequests[Math.floor(Math.random() * testRequests.length)];

                optimizedBehavior.analyze(ip, req);
                await optimizedGeo.analyze(ip);
            }

            // Periodic cleanup
            if (round % 10 === 0) {
                cacheManager.cleanup();
            }
        }

        const duration = timer.end();
        const stats = cacheManager.getStats();

        expect(duration).toBeLessThan(5000); // Should handle 5000 requests in under 5 seconds
        expect(stats.totalMemoryUsage).toBeLessThan(50 * 1024 * 1024); // Under 50MB estimated

        console.log(`\nMemory Efficiency Test:`);
        console.log(`  Duration: ${duration.toFixed(2)}ms`);
        console.log(`  Memory usage: ${(stats.totalMemoryUsage / 1024 / 1024).toFixed(2)}MB`);
        console.log(`  Cache hit rates: Geo ${(stats.geo.hitRate * 100).toFixed(1)}%, Sessions ${(stats.sessions.hitRate * 100).toFixed(1)}%`);
    });

    test('Scalability Benchmark', async () => {
        const optimizedBehavior = new OptimizedBehaviorAnalyzer(cacheManager);
        const optimizedGeo = new OptimizedGeoAnalyzer(cacheManager);
        const optimizedFingerprint = new OptimizedHTTPFingerprintAnalyzer(cacheManager);

        await optimizedGeo.initialize();

        const scalabilityTests = [
            { name: '100 requests', count: 100 },
            { name: '500 requests', count: 500 },
            { name: '1000 requests', count: 1000 },
            { name: '2000 requests', count: 2000 }
        ];

        for (const test of scalabilityTests) {
            const timer = performanceMonitor.startTiming(`scalability-${test.name}`);

            const promises: Promise<void>[] = [];
            for (let i = 0; i < test.count; i++) {
                const ip = testIPs[i % testIPs.length];
                const req = testRequests[i % testRequests.length];

                promises.push(
                    Promise.resolve().then(async () => {
                        optimizedBehavior.analyze(ip, req);
                        optimizedFingerprint.analyze(req);
                        await optimizedGeo.analyze(ip);
                    })
                );
            }

            await Promise.all(promises);
            const duration = timer.end();

            const throughput = test.count / (duration / 1000); // requests per second

            console.log(`\n${test.name}:`);
            console.log(`  Duration: ${duration.toFixed(2)}ms`);
            console.log(`  Throughput: ${throughput.toFixed(0)} req/sec`);

            expect(throughput).toBeGreaterThan(50); // Should handle at least 50 req/sec
        }
    });

    test('Cache Performance Under Different Hit Ratios', async () => {
        const optimizedGeo = new OptimizedGeoAnalyzer(cacheManager);
        await optimizedGeo.initialize();

        const scenarios = [
            { name: 'Low hit ratio (10%)', ipPoolSize: 1000 },
            { name: 'Medium hit ratio (50%)', ipPoolSize: 200 },
            { name: 'High hit ratio (90%)', ipPoolSize: 20 }
        ];

        for (const scenario of scenarios) {
            const ipPool = testIPs.slice(0, scenario.ipPoolSize);

            // Warm up cache
            for (const ip of ipPool.slice(0, 10)) {
                await optimizedGeo.analyze(ip);
            }

            const timer = performanceMonitor.startTiming(`cache-${scenario.name}`);

            for (let i = 0; i < 500; i++) {
                const ip = ipPool[Math.floor(Math.random() * ipPool.length)];
                await optimizedGeo.analyze(ip);
            }

            const duration = timer.end();
            const stats = cacheManager.getStats();

            console.log(`\n${scenario.name}:`);
            console.log(`  Duration: ${duration.toFixed(2)}ms`);
            console.log(`  Hit rate: ${(stats.geo.hitRate * 100).toFixed(1)}%`);
            console.log(`  Avg per request: ${(duration / 500).toFixed(2)}ms`);
        }
    });

    test('Performance Regression Detection', async () => {
        const optimizedBehavior = new OptimizedBehaviorAnalyzer(cacheManager);
        const baselineIterations = 1000;

        // Establish baseline
        const baselineTimes: number[] = [];
        for (let i = 0; i < baselineIterations; i++) {
            const ip = testIPs[i % testIPs.length];
            const req = testRequests[i % testRequests.length];

            const start = performance.now();
            optimizedBehavior.analyze(ip, req);
            const end = performance.now();

            baselineTimes.push(end - start);
        }

        const baselineAvg = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;
        const baselineP95 = baselineTimes.sort((a, b) => a - b)[Math.floor(baselineTimes.length * 0.95)];

        // Test current performance
        const currentTimes: number[] = [];
        for (let i = 0; i < baselineIterations; i++) {
            const ip = testIPs[i % testIPs.length];
            const req = testRequests[i % testRequests.length];

            const start = performance.now();
            optimizedBehavior.analyze(ip, req);
            const end = performance.now();

            currentTimes.push(end - start);
        }

        const currentAvg = currentTimes.reduce((a, b) => a + b, 0) / currentTimes.length;
        const currentP95 = currentTimes.sort((a, b) => a - b)[Math.floor(currentTimes.length * 0.95)];

        // Check for regression (allow 10% variance)
        const avgRegression = currentAvg / baselineAvg;
        const p95Regression = currentP95 / baselineP95;

        console.log(`\nRegression Test:`);
        console.log(`  Baseline avg: ${baselineAvg.toFixed(2)}ms, P95: ${baselineP95.toFixed(2)}ms`);
        console.log(`  Current avg: ${currentAvg.toFixed(2)}ms, P95: ${currentP95.toFixed(2)}ms`);
        console.log(`  Avg regression: ${avgRegression.toFixed(2)}x, P95 regression: ${p95Regression.toFixed(2)}x`);

        expect(avgRegression).toBeLessThan(1.1); // No more than 10% regression
        expect(p95Regression).toBeLessThan(1.2); // P95 can be slightly more variable
    });

    test('Resource Cleanup Efficiency', async () => {
        const testCache = new CacheManager({
            maxSessionEntries: 1000,
            maxGeoEntries: 1000,
            maxFingerprintEntries: 1000,
            sessionTimeout: 100, // Very short timeout for testing
            geoTTL: 100,
            fingerprintTTL: 100,
            cleanupInterval: 50
        });

        // Fill cache with data
        for (let i = 0; i < 500; i++) {
            const ip = `192.168.${Math.floor(i / 255)}.${i % 255}`;
            testCache.setSession(ip, {
                ip,
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                requestCount: 1,
                requests: [],
                fingerprints: new Set(),
                suspicionHistory: []
            });

            testCache.setGeoLocation(ip, {
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

        const statsBefore = testCache.getStats();

        // Wait for expiration
        await new Promise(resolve => setTimeout(resolve, 200));

        const timer = performanceMonitor.startTiming('cleanup-efficiency');
        testCache.cleanup();
        const duration = timer.end();

        const statsAfter = testCache.getStats();

        expect(duration).toBeLessThan(50); // Cleanup should be fast
        expect(statsAfter.sessions.size).toBeLessThan(statsBefore.sessions.size);
        expect(statsAfter.geo.size).toBeLessThan(statsBefore.geo.size);

        console.log(`\nCleanup Efficiency:`);
        console.log(`  Duration: ${duration.toFixed(2)}ms`);
        console.log(`  Sessions cleaned: ${statsBefore.sessions.size - statsAfter.sessions.size}`);
        console.log(`  Geo entries cleaned: ${statsBefore.geo.size - statsAfter.geo.size}`);

        testCache.shutdown();
    });
});

// Helper functions
function generateTestRequests(count: number): Request[] {
    const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
    ];

    const paths = ['/api/users', '/api/posts', '/api/comments', '/dashboard', '/profile', '/settings'];
    const methods = ['GET', 'POST', 'PUT', 'DELETE'];

    return Array.from({ length: count }, (_, i) => ({
        headers: {
            'user-agent': userAgents[i % userAgents.length],
            'accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.5',
            'accept-encoding': 'gzip, deflate, br',
            'connection': 'keep-alive',
            'cache-control': 'no-cache'
        },
        rawHeaders: [
            'User-Agent', userAgents[i % userAgents.length],
            'Accept', 'application/json,text/html...',
            'Accept-Language', 'en-US,en;q=0.5'
        ],
        path: paths[i % paths.length],
        method: methods[i % methods.length],
        get: function (header: string) { return this.headers[header.toLowerCase()]; }
    })) as Request[];
}

function generateTestIPs(count: number): string[] {
    const ips: string[] = [];

    for (let i = 0; i < count; i++) {
        // Generate realistic IP distribution
        if (i % 10 === 0) {
            // Some public IPs
            const publicIPs = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9'];
            ips.push(publicIPs[i % publicIPs.length]);
        } else {
            // Generate private/random IPs
            const a = Math.floor(Math.random() * 255);
            const b = Math.floor(Math.random() * 255);
            const c = Math.floor(Math.random() * 255);
            const d = Math.floor(Math.random() * 255);
            ips.push(`${a}.${b}.${c}.${d}`);
        }
    }

    return ips;
}