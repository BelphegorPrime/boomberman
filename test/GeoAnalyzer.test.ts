import { GeoAnalyzer } from '../src/detection/analyzers/GeoAnalyzer.js';

describe('GeoAnalyzer', () => {
    let geoAnalyzer: GeoAnalyzer;

    beforeEach(async () => {
        geoAnalyzer = new GeoAnalyzer();
        await geoAnalyzer.initialize();
    });

    describe('initialization', () => {
        it('should initialize successfully', async () => {
            const analyzer = new GeoAnalyzer();
            await analyzer.initialize();
            expect(analyzer.isInitialized()).toBe(true);
        });

        it('should throw error when analyzing without initialization', async () => {
            const analyzer = new GeoAnalyzer();
            await expect(analyzer.analyze('8.8.8.8')).rejects.toThrow('GeoAnalyzer not initialized');
        });

        it('should return version information', () => {
            expect(geoAnalyzer.getVersion()).toBe('1.0.1');
        });

        it('should indicate if using real MaxMind databases', () => {
            expect(typeof geoAnalyzer.isUsingRealDatabases()).toBe('boolean');
        });

        it('should have updateDatabases method', () => {
            expect(typeof geoAnalyzer.updateDatabases).toBe('function');
        });
    });

    describe('IP validation', () => {
        it('should handle invalid IP addresses gracefully', async () => {
            const result = await geoAnalyzer.analyze('invalid-ip');
            expect(result.country).toBe('unknown');
            expect(result.region).toBe('unknown');
            expect(result.city).toBe('unknown');
            expect(result.riskScore).toBe(0);
        });

        it('should handle empty IP address', async () => {
            const result = await geoAnalyzer.analyze('');
            expect(result.country).toBe('unknown');
            expect(result.riskScore).toBe(0);
        });

        it('should handle malformed IP addresses', async () => {
            const malformedIPs = ['999.999.999.999', '192.168.1', '192.168.1.1.1'];

            for (const ip of malformedIPs) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result.country).toBe('unknown');
            }
        });
    });

    describe('private IP handling', () => {
        it('should identify localhost correctly', async () => {
            const result = await geoAnalyzer.analyze('127.0.0.1');
            expect(result.country).toBe('local');
            expect(result.region).toBe('local');
            expect(result.city).toBe('local');
            expect(result.riskScore).toBe(0);
            expect(result.isVPN).toBe(false);
            expect(result.isProxy).toBe(false);
            expect(result.isHosting).toBe(false);
        });

        it('should identify IPv6 localhost correctly', async () => {
            const result = await geoAnalyzer.analyze('::1');
            expect(result.country).toBe('local');
            expect(result.riskScore).toBe(0);
        });

        it('should identify private IP ranges correctly', async () => {
            const privateIPs = ['10.0.0.1', '172.16.0.1', '192.168.1.1'];

            for (const ip of privateIPs) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result.country).toBe('local');
                expect(result.riskScore).toBe(0);
            }
        });
    });

    describe('geographic analysis', () => {
        it('should return valid geographic data for public IPs', async () => {
            const result = await geoAnalyzer.analyze('8.8.8.8');

            expect(result.country).toBeDefined();
            expect(result.region).toBeDefined();
            expect(result.city).toBeDefined();
            expect(result.asn).toBeGreaterThan(0);
            expect(result.organization).toBeDefined();
            expect(typeof result.riskScore).toBe('number');
            expect(result.riskScore).toBeGreaterThanOrEqual(0);
            expect(result.riskScore).toBeLessThanOrEqual(100);
        });

        it('should provide consistent results for the same IP', async () => {
            const ip = '1.1.1.1';
            const result1 = await geoAnalyzer.analyze(ip);
            const result2 = await geoAnalyzer.analyze(ip);

            expect(result1.country).toBe(result2.country);
            expect(result1.region).toBe(result2.region);
            expect(result1.city).toBe(result2.city);
            expect(result1.asn).toBe(result2.asn);
            expect(result1.riskScore).toBe(result2.riskScore);
        });
    });

    describe('VPN detection', () => {
        it('should detect VPN providers in organization names', async () => {
            // This test relies on the simulation returning specific organizations
            // In a real implementation, you would mock the MaxMind database responses
            const results = await Promise.all([
                geoAnalyzer.analyze('1.1.1.1'),
                geoAnalyzer.analyze('2.2.2.2'),
                geoAnalyzer.analyze('3.3.3.3'),
                geoAnalyzer.analyze('4.4.4.4'),
                geoAnalyzer.analyze('5.5.5.5')
            ]);

            // At least one result should have infrastructure detection
            const hasInfrastructureDetection = results.some(result =>
                result.isVPN || result.isProxy || result.isHosting
            );

            expect(hasInfrastructureDetection).toBe(true);
        });
    });

    describe('hosting provider detection', () => {
        it('should detect known hosting ASNs', async () => {
            // Test multiple IPs to increase chance of hitting hosting ASNs
            const results = await Promise.all([
                geoAnalyzer.analyze('8.8.8.8'),
                geoAnalyzer.analyze('1.1.1.1'),
                geoAnalyzer.analyze('4.4.4.4'),
                geoAnalyzer.analyze('9.9.9.9'),
                geoAnalyzer.analyze('208.67.222.222')
            ]);

            // At least one should be detected as hosting (based on our simulation)
            const hasHostingDetection = results.some(result => result.isHosting);
            expect(hasHostingDetection).toBe(true);
        });
    });

    describe('risk scoring', () => {
        it('should calculate risk scores within valid range', async () => {
            const testIPs = [
                '8.8.8.8',
                '1.1.1.1',
                '208.67.222.222',
                '9.9.9.9',
                '4.4.4.4'
            ];

            for (const ip of testIPs) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                expect(result.riskScore).toBeLessThanOrEqual(100);
            }
        });

        it('should assign higher risk scores to VPN/proxy/hosting IPs', async () => {
            const results = await Promise.all([
                geoAnalyzer.analyze('1.1.1.1'),
                geoAnalyzer.analyze('2.2.2.2'),
                geoAnalyzer.analyze('3.3.3.3'),
                geoAnalyzer.analyze('4.4.4.4'),
                geoAnalyzer.analyze('5.5.5.5')
            ]);

            // Find results with infrastructure flags
            const infrastructureResults = results.filter(r => r.isVPN || r.isProxy || r.isHosting);
            const regularResults = results.filter(r => !r.isVPN && !r.isProxy && !r.isHosting);

            if (infrastructureResults.length > 0 && regularResults.length > 0) {
                const avgInfrastructureRisk = infrastructureResults.reduce((sum, r) => sum + r.riskScore, 0) / infrastructureResults.length;
                const avgRegularRisk = regularResults.reduce((sum, r) => sum + r.riskScore, 0) / regularResults.length;

                expect(avgInfrastructureRisk).toBeGreaterThanOrEqual(avgRegularRisk);
            }
        });

        it('should assign zero risk to local IPs', async () => {
            const localIPs = ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1'];

            for (const ip of localIPs) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result.riskScore).toBe(0);
            }
        });
    });

    describe('error handling', () => {
        it('should handle analysis errors gracefully', async () => {
            // Test with various edge cases
            const edgeCases = [
                '0.0.0.0',
                '255.255.255.255',
                '192.0.2.1', // TEST-NET-1
                '198.51.100.1', // TEST-NET-2
                '203.0.113.1' // TEST-NET-3
            ];

            for (const ip of edgeCases) {
                const result = await geoAnalyzer.analyze(ip);
                expect(result).toBeDefined();
                expect(typeof result.riskScore).toBe('number');
                expect(result.riskScore).toBeGreaterThanOrEqual(0);
                expect(result.riskScore).toBeLessThanOrEqual(100);
            }
        });
    });

    describe('data structure validation', () => {
        it('should return complete GeoLocation objects', async () => {
            const result = await geoAnalyzer.analyze('8.8.8.8');

            // Verify all required properties exist
            expect(result).toHaveProperty('country');
            expect(result).toHaveProperty('region');
            expect(result).toHaveProperty('city');
            expect(result).toHaveProperty('isVPN');
            expect(result).toHaveProperty('isProxy');
            expect(result).toHaveProperty('isHosting');
            expect(result).toHaveProperty('isTor');
            expect(result).toHaveProperty('riskScore');
            expect(result).toHaveProperty('asn');
            expect(result).toHaveProperty('organization');

            // Verify data types
            expect(typeof result.country).toBe('string');
            expect(typeof result.region).toBe('string');
            expect(typeof result.city).toBe('string');
            expect(typeof result.isVPN).toBe('boolean');
            expect(typeof result.isProxy).toBe('boolean');
            expect(typeof result.isHosting).toBe('boolean');
            expect(typeof result.isTor).toBe('boolean');
            expect(typeof result.riskScore).toBe('number');
            expect(typeof result.asn).toBe('number');
            expect(typeof result.organization).toBe('string');
        });
    });

    describe('performance', () => {
        it('should analyze IPs within reasonable time', async () => {
            const startTime = process.hrtime.bigint();

            await geoAnalyzer.analyze('8.8.8.8');

            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1_000_000; // Convert to milliseconds

            // Should complete within 100ms (generous for simulation)
            expect(duration).toBeLessThan(100);
        });

        it('should handle multiple concurrent analyses', async () => {
            const testIPs = [
                '8.8.8.8',
                '1.1.1.1',
                '208.67.222.222',
                '9.9.9.9',
                '4.4.4.4'
            ];

            const startTime = process.hrtime.bigint();

            const results = await Promise.all(
                testIPs.map(ip => geoAnalyzer.analyze(ip))
            );

            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1_000_000;

            expect(results).toHaveLength(testIPs.length);
            expect(duration).toBeLessThan(500); // Should handle 5 concurrent requests quickly

            // All results should be valid
            results.forEach(result => {
                expect(result).toBeDefined();
                expect(typeof result.riskScore).toBe('number');
            });
        });
    });
});