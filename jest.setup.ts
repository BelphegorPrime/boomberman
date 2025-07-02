import express, { Request } from 'express';
import http from 'http';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

// Export these so tests can import and inspect them
export let webhookServer: http.Server | null = null;
export let webhookPort: number | null = null;
export let receivedPayload: ReturnType<Request['body']> | null = null;

beforeAll((done) => {
  const webhookApp = express();
  webhookApp.use(express.json());

  receivedPayload = null;

  webhookApp.post('/alert', (req, res) => {
    receivedPayload = req.body;
    res.status(200).send('OK');
  });

  webhookServer = webhookApp.listen(0, () => {
    const serverData = webhookServer!.address();
    webhookPort =
      serverData && typeof serverData !== 'string' ? serverData.port : 0;
    process.env.WEBHOOK_URL = `http://localhost:${webhookPort}/alert`;
    done();
  });
});

afterAll((done) => {
  if (webhookServer) {
    webhookServer.close(() => {
      webhookServer = null;
      webhookPort = null;
      delete process.env.WEBHOOK_URL;
      done();
    });
  } else {
    done();
  }
});
