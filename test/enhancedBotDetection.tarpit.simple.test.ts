import request from 'supertest';
import app from '../src/server.js';
import { clearBanData, getBanEntry, isBanned } from '../src/utils/logger/banFile.js';

describe('Enhanced Bot Detection - Tarpit Integration (Simple)', () => {
    beforeEach(() => {
        clearBanData();
    });

    afterEach(() => {
        clearBanData();
    });

    test('should integrate enhanced detection with tarpit middleware', async () => {
        const testIp = '192.168.1.200';

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
        expect(banEntry?.confidence).toBeGreaterThan(0);
    }, 15000);

    test('should ban IP after multiple suspicious requests', async () => {
        const testIp = '192.168.1.201';

        const suspiciousHeaders = {
            'User-Agent': 'python-requests/2.28.1',
            'X-Forwarded-For': testIp,
        };

        // Make 2 requests to trigger ban (high confidence, medium score)
        await request(app)
            .get('/tool/tarpit')
            .set(suspiciousHeaders)
            .timeout(10000);

        expect(isBanned(testIp)).toBe(false); // Not banned after 1 request

        await request(app)
            .get('/tool/tarpit')
            .set(suspiciousHeaders)
            .timeout(10000);

        expect(isBanned(testIp)).toBe(true); // Should be banned after 2 requests

        // Third request should be blocked at server level
        const response = await request(app)
            .get('/api/health')
            .set(suspiciousHeaders);

        expect(response.status).toBe(403);
        expect(response.text).toContain('banned');
    }, 25000);

    test('should maintain backward compatibility with legacy detection', async () => {
        const testIp = '192.168.1.202';

        // Request that would trigger legacy detection
        const legacyBotHeaders = {
            'User-Agent': 'curl/7.68.0', // Known bot in legacy system
            'X-Forwarded-For': testIp,
        };

        const response = await request(app)
            .get('/tool/tarpit')
            .set(legacyBotHeaders)
            .timeout(10000);

        // Should still be tarpitted
        expect(response.status).toBe(429);

        // Check that ban data was recorded
        const banEntry = getBanEntry(testIp);
        expect(banEntry).toBeDefined();
        expect(banEntry?.count).toBe(1);
    }, 15000);

    test('should include enhanced detection metadata in responses', async () => {
        const testIp = '192.168.1.203';

        const response = await request(app)
            .get('/tool/tarpit')
            .set({
                'User-Agent': 'python-requests/2.28.1',
                'X-Forwarded-For': testIp,
            })
            .timeout(10000);

        expect(response.status).toBe(429);

        // Should have detection score headers if enhanced detection was used
        if (response.headers['x-detection-score']) {
            expect(response.headers['x-detection-score']).toBeDefined();
            expect(response.headers['x-detection-confidence']).toBeDefined();
            expect(response.headers['x-detection-fingerprint']).toBeDefined();
        }
    }, 15000);
});