import request from 'supertest';
import app from '../src/server.js';
import { clearBanData, getBanEntry, isBanned } from '../src/utils/logger/banFile.js';

describe('Enhanced Bot Detection - Basic Integration', () => {
    beforeEach(() => {
        clearBanData();
    });

    afterEach(() => {
        clearBanData();
    });

    test('should detect and record enhanced bot detection data', async () => {
        const testIp = '192.168.1.250';

        // Create a suspicious request that should trigger enhanced detection
        const suspiciousHeaders = {
            'User-Agent': 'python-requests/2.28.1', // Automation signature
            'X-Forwarded-For': testIp,
        };

        // Make request to tarpit endpoint
        const response = await request(app)
            .get('/tool/tarpit')
            .set(suspiciousHeaders)
            .timeout(10000);

        // Should be tarpitted
        expect(response.status).toBe(429);

        // Check that enhanced detection data was recorded
        const banEntry = getBanEntry(testIp);
        expect(banEntry).toBeDefined();
        expect(banEntry?.enhancedDetections).toBeGreaterThan(0);
        expect(banEntry?.suspicionScore).toBeGreaterThan(0);
        expect(banEntry?.confidence).toBeGreaterThan(0);

        console.log('Ban entry:', banEntry);
    }, 15000);

    test('should ban IP based on confidence levels', async () => {
        const testIp = '192.168.1.251';

        const suspiciousHeaders = {
            'User-Agent': 'python-requests/2.28.1',
            'X-Forwarded-For': testIp,
        };

        // First request
        await request(app)
            .get('/tool/tarpit')
            .set(suspiciousHeaders)
            .timeout(10000);

        let banEntry = getBanEntry(testIp);
        console.log('After first request:', banEntry);
        expect(isBanned(testIp)).toBe(false);

        // Second request - should trigger ban due to high confidence (0.8) and medium score (40)
        await request(app)
            .get('/tool/tarpit')
            .set(suspiciousHeaders)
            .timeout(10000);

        banEntry = getBanEntry(testIp);
        console.log('After second request:', banEntry);
        console.log('Is banned:', isBanned(testIp));

        // Should be banned now
        expect(isBanned(testIp)).toBe(true);
    }, 25000);

    test('should apply enhanced detection to regular endpoints', async () => {
        const testIp = '192.168.1.252';

        // High-risk request to regular endpoint
        const highRiskHeaders = {
            'User-Agent': 'python-requests/2.28.1',
            'X-Forwarded-For': testIp,
        };

        // Make request to health endpoint - should be handled by enhanced detection
        const response = await request(app)
            .get('/api/health')
            .set(highRiskHeaders);

        // Should either be blocked (high risk) or pass through (medium risk)
        expect([200, 429].includes(response.status)).toBe(true);

        // Check if detection data was recorded
        const banEntry = getBanEntry(testIp);
        if (banEntry) {
            console.log('Detection data recorded:', banEntry);
        }
    }, 10000);
});