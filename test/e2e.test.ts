import request from 'supertest';
import app from '../src/server';
import { isBanned, banIP } from '../src/utils/logger';
import fs from 'fs';
import path from 'path';

afterEach(() => {
    const banFile = path.resolve(__dirname, './data/banned.json');
    if (fs.existsSync(banFile)) {
        fs.unlinkSync(banFile);
    }
});

describe('Boomberman e2e tests', () => {
    test('Accessing honeypot endpoint triggers ban', async () => {
        const res = await request(app).get('/tool/pot/admin').set('X-Forwarded-For', '1.2.3.4');
        expect(res.status).toBe(403);
        expect(isBanned('1.2.3.4')).toBe(true);
    });

    test('Download test bomb', async () => {
        const res = await request(app).get('/public/harmless-bomb.zip');
        expect([200, 404]).toContain(res.status); // 404 if file is not present
    });

    test('Banned IP is recognized', () => {
        banIP('5.6.7.8');
        expect(isBanned('5.6.7.8')).toBe(true);
    });
});
