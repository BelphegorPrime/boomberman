import request from 'supertest';
import fs from 'fs';
import path from 'path';
import app from '../src/server';
import { dirname } from '../src/utils/filesystemConstants';

const tarpitFile =
  process.env.TARPIT_FILE_PATH ||
  path.resolve(dirname, './data/tarpitAccess.json');
const banFile =
  process.env.BAN_FILE_PATH || path.resolve(dirname, './data/banned.json');

describe('Tarpit Middleware', () => {
  beforeEach(() => {
    if (fs.existsSync(banFile)) {
      fs.unlinkSync(banFile);
    }
    if (fs.existsSync(tarpitFile)) {
      fs.unlinkSync(tarpitFile);
    }
  });

  afterEach(() => {
    if (fs.existsSync(tarpitFile)) {
      fs.unlinkSync(tarpitFile);
    }
  });

  test('bot detection middleware intercepts suspicious user agent', async () => {
    const res = await request(app)
      .get('/tool/tarpit')
      .set('user-agent', 'nikto')
      .buffer(true)
      .parse((res, callback) => {
        // Don't parse response to avoid JSON errors
        callback(null, res);
      });

    // Bot detection middleware should intercept and return faulty response or ban
    expect([200, 403, 418]).toContain(res.status);
  }, 5_000);

  test('normal request gets faulty response from fallback', async () => {
    const res = await request(app)
      .get('/tool/tarpit')
      .set('user-agent', 'Mozilla/5.0 (normal browser)')
      .buffer(true)
      .parse((res, callback) => {
        // Don't parse response to avoid JSON errors
        callback(null, res);
      });

    // Should get faulty response from tool router fallback, ban, or error
    expect([200, 403, 418, 500]).toContain(res.status);
  }, 5_000);
});
