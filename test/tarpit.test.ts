import request from 'supertest';
import fs from 'fs';
import path from 'path';
import app from '../src/server';

const tarpitFile = process.env.TARPIT_FILE_PATH || path.resolve(__dirname, './data/tarpitAccess.json');
const banFile = process.env.BAN_FILE_PATH || path.resolve(__dirname, './data/banned.json');

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

    test('delays second request if within minInterval', async () => {
        const start = Date.now();
        const res = await request(app).get('/tool/tarpit').set("user-agent", "nikto")
        const duration = Date.now() - start;

        expect(res.status).toBe(429);

        expect(duration).toBeGreaterThanOrEqual(1000);
    }, 30_000);

    test('allows request after minInterval', async () => {
        await request(app).get('/tool/tarpit');

        await new Promise((r) => setTimeout(r, 31_000));

        const start = Date.now();
        const res = await request(app).get('/tool/tarpit');
        const duration = Date.now() - start;

        expect(res.status).toBe(404);
        expect(duration).toBeLessThan(100);
    }, 60_000);
});
