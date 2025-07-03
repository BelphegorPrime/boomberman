import request from 'supertest';
import app from '../src/server';

describe('Health Check', () => {
  it('should return 200 OK and status ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body).toEqual({ status: 'ok', timestamp: expect.any(String) });
  });
});
