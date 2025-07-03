import request from 'supertest';
import express from 'express';
import { defaultLimiter, strictLimiter } from '../src/middleware/rateLimiter';

describe('Rate Limiter Middleware', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
  });

  describe('defaultLimiter', () => {
    it('should allow 10 requests within a minute', async () => {
      app.use(defaultLimiter);
      app.get('/', (req, res) => res.send('OK'));

      for (let i = 0; i < 10; i++) {
        const res = await request(app).get('/');
        expect(res.statusCode).toEqual(200);
      }
    });

    it('should block requests after 10 within a minute', async () => {
      app.use(defaultLimiter);
      app.get('/', (req, res) => res.send('OK'));

      for (let i = 0; i < 10; i++) {
        await request(app).get('/');
      }

      const res = await request(app).get('/');
      expect(res.statusCode).toEqual(429);
    });
  });

  describe('strictLimiter', () => {
    it('should allow 3 requests within a minute', async () => {
      app.use(strictLimiter);
      app.get('/', (req, res) => res.send('OK'));

      for (let i = 0; i < 3; i++) {
        const res = await request(app).get('/');
        expect(res.statusCode).toEqual(200);
      }
    });

    it('should block requests after 3 within a minute', async () => {
      app.use(strictLimiter);
      app.get('/', (req, res) => res.send('OK'));

      for (let i = 0; i < 3; i++) {
        await request(app).get('/');
      }

      const res = await request(app).get('/');
      expect(res.statusCode).toEqual(429);
    });
  });
});
