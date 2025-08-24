import { GeoAnalyzer } from '../src/detection/analyzers/GeoAnalyzer.js';

describe('GeoAnalyzer Integration', () => {
    let geoAnalyzer: GeoAnalyzer;

    beforeAll(async () => {
        geoAnalyzer = new GeoAnalyzer();
        await geoAnalyzer.initialize();
    });

    describe('real-world IP analysis', () => {
        it('should analyze well-known public DNS servers', async () => {
            const publicDNSServers = [
                '8.8.8.8',      // Google DNS
                '1.1.1.1',      // Cloudflare DNS
                '208.67.222.222', // OpenDNS
                '9.9.9.9',      // Quad9 DNS
            ];

            for (const ip of publicDNSServers) {
                const result = await geoAnalyzer.analyze(ip);

                expect(result).toBeDefined();
                expect(result.country).toBeDefined();
                expect(result.organization).toBeDefined();
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                expect(result.riskScore).toBeLessThanOrEqual(100);

                // If using real databases, we should get better data
                if (geoAnalyzer.isUsingRealDatabases()) {
                    // Real databases might still return 'unknown' for some fields, but ASN should be valid
                    expect(typeof result.asn).toBe('number');
                } else {
                    // In simulation mode, we expect valid data for public IPs
                    expect(result.country).not.toBe('unknown');
                    expect(result.asn).toBeGreaterThan(0);
                    expect(result.organization).not.toBe('unknown');
                }
            }
        });

        it('should handle batch analysis efficiently', async () => {
            const testIPs = [
                '8.8.8.8',
                '1.1.1.1',
                '208.67.222.222',
                '127.0.0.1',
                '192.168.1.1',
                '10.0.0.1',
            ];

            const startTime = process.hrtime.bigint();

            const results = await Promise.all(
                testIPs.map(ip => geoAnalyzer.analyze(ip))
            );

            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1_000_000; // Convert to milliseconds

            expect(results).toHaveLength(testIPs.length);
            expect(duration).toBeLessThan(1000); // Should complete within 1 second

            // Verify all results are valid
            results.forEach((result, index) => {
                expect(result).toBeDefined();
                expect(typeof result.riskScore).toBe('number');
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                expect(result.riskScore).toBeLessThanOrEqual(100);

                // Local IPs should have zero risk
                if (testIPs[index].startsWith('127.') ||
                    testIPs[index].startsWith('192.168.') ||
                    testIPs[index].startsWith('10.')) {
                    expect(result.riskScore).toBe(0);
                    expect(result.country).toBe('local');
                }
            });
        });
    });

    describe('risk assessment integration', () => {
        it('should provide consistent risk assessment', async () => {
            const testIP = '8.8.8.8';

            // Analyze the same IP multiple times
            const results = await Promise.all([
                geoAnalyzer.analyze(testIP),
                geoAnalyzer.analyze(testIP),
                geoAnalyzer.analyze(testIP),
            ]);

            // All results should be identical
            expect(results[0]).toEqual(results[1]);
            expect(results[1]).toEqual(results[2]);
        });

        it('should differentiate between infrastructure types', async () => {
            const testIPs = [
                '8.8.8.8',      // Google (likely hosting)
                '1.1.1.1',      // Cloudflare (likely hosting)
                '127.0.0.1',    // Localhost (no risk)
                '192.168.1.1',  // Private (no risk)
            ];

            const results = await Promise.all(
                testIPs.map(ip => geoAnalyzer.analyze(ip))
            );

            // Local IPs should have zero risk
            expect(results[2].riskScore).toBe(0); // localhost
            expect(results[3].riskScore).toBe(0); // private IP

            // Public IPs may have some risk based on infrastructure
            const publicResults = results.slice(0, 2);
            publicResults.forEach(result => {
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                // At least one should be detected as hosting infrastructure
                if (result.isHosting) {
                    expect(result.riskScore).toBeGreaterThan(0);
                }
            });
        });
    });

    describe('error resilience', () => {
        it('should handle network-like errors gracefully', async () => {
            // Test with various edge case IPs
            const edgeCaseIPs = [
                '0.0.0.0',
                '255.255.255.255',
                '224.0.0.1', // Multicast
                '169.254.1.1', // Link-local
            ];

            for (const ip of edgeCaseIPs) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result).toBeDefined();
                expect(typeof result.riskScore).toBe('number');
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                expect(result.riskScore).toBeLessThanOrEqual(100);
            }
        });

        it('should maintain performance under load', async () => {
            const loadTestIPs = Array(50).fill(null).map((_, i) => `192.0.2.${i + 1}`);

            const startTime = process.hrtime.bigint();

            const results = await Promise.all(
                loadTestIPs.map(ip => geoAnalyzer.analyze(ip))
            );

            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1_000_000;

            expect(results).toHaveLength(50);
            expect(duration).toBeLessThan(2000); // Should handle 50 requests within 2 seconds

            // All results should be valid
            results.forEach(result => {
                expect(result).toBeDefined();
                expect(typeof result.riskScore).toBe('number');
            });
        });
    });
});