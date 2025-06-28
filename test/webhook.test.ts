import request from 'supertest';
import app from '../src/server'; // your express app
import { receivedPayload } from '../jest.setup';

describe('sendWebhookAlert E2E', () => {
    test('hitting /admin triggers webhook alert with correct payload', async () => {
        const testIp = '1.2.3.4';

        // Trigger honeypot endpoint which calls sendWebhookAlert internally
        const res = await request(app).get('/tool/pot/admin').set('X-Forwarded-For', testIp);

        expect(res.status).toBe(403); // banned response

        // Wait a tiny bit for async webhook to complete (optional, depending on your code)
        await new Promise((r) => setTimeout(r, 50));

        // Assert webhook received the alert
        expect(receivedPayload).toBeDefined();
        expect(receivedPayload.ip).toBe(testIp);
        expect(receivedPayload.type).toBe('HONEYPOT_HIT');
        expect(receivedPayload.target).toBe('/admin');
        expect(typeof receivedPayload.timestamp).toBe('string');
    });
});
