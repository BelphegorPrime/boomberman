import express from 'express';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

// Global variables for tests
let webhookServer = null;
let webhookPort = null;

beforeAll((done) => {
  const webhookApp = express();
  webhookApp.use(express.json());

  global.receivedPayload = null;

  webhookApp.post('/alert', (req, res) => {
    global.receivedPayload = req.body;
    res.status(200).send('OK');
  });

  webhookServer = webhookApp.listen(0, () => {
    const serverData = webhookServer.address();
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

      // Clear all timers and scheduled jobs
      if (typeof global.gc === 'function') {
        global.gc();
      }

      done();
    });
  } else {
    done();
  }
});
