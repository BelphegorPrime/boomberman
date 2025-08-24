import request from 'supertest';
import app from '../src/server';
import { isBanned, banIP, clearBanData } from '../src/utils/logger/banFile';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

beforeEach(() => {
  // Clear in-memory ban data before each test
  clearBanData();
});

afterEach(() => {
  // Clear in-memory ban data
  clearBanData();

  // Clean up ban files
  const banFile = path.resolve(__dirname, './data/banned.json');
  if (fs.existsSync(banFile)) {
    fs.unlinkSync(banFile);
  }
});

describe('Boomberman e2e tests', () => {
  test('Accessing honeypot endpoint triggers ban after 3 hits', async () => {
    const testIp = '10.0.0.1';

    // First hit - should not be banned yet
    try {
      await request(app)
        .get('/tool/pot/admin')
        .set('X-Forwarded-For', testIp)
        .responseType('blob') // Handle large responses
        .timeout(5000);
    } catch (error) {
      // Ignore response size/parsing errors, we only care about the ban logic
    }
    expect(isBanned(testIp)).toBe(false);

    // Second hit - still not banned
    try {
      await request(app)
        .get('/tool/pot/admin')
        .set('X-Forwarded-For', testIp)
        .responseType('blob')
        .timeout(5000);
    } catch (error) {
      // Ignore response size/parsing errors
    }
    expect(isBanned(testIp)).toBe(false);

    // Third hit - now banned
    try {
      await request(app)
        .get('/tool/pot/admin')
        .set('X-Forwarded-For', testIp)
        .responseType('blob')
        .timeout(5000);
    } catch (error) {
      // Ignore response size/parsing errors
    }
    expect(isBanned(testIp)).toBe(true);

    // Fourth hit - should be blocked with 403 (this should be fast and not cause size issues)
    const res4 = await request(app)
      .get('/tool/pot/admin')
      .set('X-Forwarded-For', testIp);
    expect(res4.status).toBe(403);
  });

  test('Download test bomb triggers ban after 3 downloads', async () => {
    const testIp = '9.8.7.6';

    // First download - should succeed, IP not banned yet
    const res1 = await request(app)
      .get('/public/harmless-bomb.zip')
      .set('X-Forwarded-For', testIp);
    expect(res1.status).toBe(200);
    expect(isBanned(testIp)).toBe(false);

    // Second download - should succeed, IP not banned yet
    const res2 = await request(app)
      .get('/public/harmless-bomb.zip')
      .set('X-Forwarded-For', testIp);
    expect(res2.status).toBe(200);
    expect(isBanned(testIp)).toBe(false);

    // Third download - should succeed, IP now banned
    const res3 = await request(app)
      .get('/public/harmless-bomb.zip')
      .set('X-Forwarded-For', testIp);
    expect(res3.status).toBe(200);
    expect(isBanned(testIp)).toBe(true);

    // Fourth request - should be blocked with 403
    const res4 = await request(app)
      .get('/public/harmless-bomb.zip')
      .set('X-Forwarded-For', testIp);
    expect(res4.status).toBe(403);
  });

  test('Banned IP is recognized after 3 bans', () => {
    // Ban IP 3 times to reach the threshold
    banIP('5.6.7.8');
    expect(isBanned('5.6.7.8')).toBe(false); // Count is 1

    banIP('5.6.7.8');
    expect(isBanned('5.6.7.8')).toBe(false); // Count is 2

    banIP('5.6.7.8');
    expect(isBanned('5.6.7.8')).toBe(true); // Count is 3, now banned
  });
});
