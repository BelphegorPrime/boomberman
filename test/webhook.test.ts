import request from 'supertest';
import app from '../src/server'; // your express app

// Access the receivedPayload from the global setup
declare global {
  var receivedPayload: any;
}

describe('sendWebhookAlert E2E', () => {
  test('hitting /admin triggers webhook alert with correct payload', async () => {
    const testIp = '1.2.3.4';

    // Trigger honeypot endpoint which calls sendWebhookAlert internally
    try {
      const res = await request(app)
        .get('/tool/pot/admin')
        .set('X-Forwarded-For', testIp)
        .buffer(true)
        .parse((res, callback) => {
          // Don't parse response to avoid JSON errors
          callback(null, res);
        });

      // Honeypot returns various faulty responses (200, 418, etc.)
      expect([200, 418]).toContain(res.status);
    } catch (error) {
      // Ignore JSON parsing errors from malformed responses
    }

    // Wait a tiny bit for async webhook to complete (optional, depending on your code)
    await new Promise((r) => setTimeout(r, 50));

    // Assert webhook received the alert
    expect(global.receivedPayload).toBeDefined();
    expect(global.receivedPayload.ip).toBe(testIp);
    expect(global.receivedPayload.type).toBe('HONEYPOT_HIT');
    expect(global.receivedPayload.target).toBe('/admin');
    expect(typeof global.receivedPayload.timestamp).toBe('string');
  });
});
