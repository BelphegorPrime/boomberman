import 'dotenv/config';
import './utils/logger/fileLogger.js';
import helmet from 'helmet';
import express, { Router } from 'express';
import fileRoutes from './routes/files.js';
import honeypotRoutes from './routes/honeypots.js';
import metricsRoutes from './routes/metrics.js';
import captchaRouter from './routes/captcha.js';
import toolRouter from './routes/tool.js';
import { logThreat } from './utils/logger/logger.js';
import { tarpit } from './middleware/tarpit.js';
import { defaultLimiter, strictLimiter } from './middleware/rateLimiter.js';
import { generateFaultyResponse } from './utils/generateFaultyResponse.js';
import {
  generateNewFakeResponse,
  startHourlyFakeResponseTask,
} from './ai/fakeResponseManager.js';

import { isBanned } from './utils/logger/banFile.js';
import { enhancedBotDetectionMiddleware } from './middleware/enhancedBotDetection.js';

const app = express();

app.use(helmet());
app.use(express.json());

app.get('/api/health', (req, res) => {
  return res
    .status(200)
    .json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(defaultLimiter);

// Block banned IPs
app.use((req, res, next) => {
  const ip =
    req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown';

  req.realIp = ip;

  if (isBanned(ip)) {
    return res.status(403).send('Your IP has been banned.');
  }

  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const duration = Number(process.hrtime.bigint() - start) / 1_000_000;
    console.log(`${ip} - ${duration.toFixed(2)} ms`);
  });

  next();
});

// Enhanced bot detection middleware - comprehensive threat analysis
app.use(enhancedBotDetectionMiddleware);

app.use('/public', fileRoutes);
app.use('/tool/tarpit', tarpit, (req, res) => {
  res.status(200).json({ message: 'Tarpit test endpoint' });
});
app.use('/tool/pot', honeypotRoutes);
app.use('/tool/captcha', captchaRouter);
app.use('/metrics', strictLimiter, metricsRoutes);

if (process.env.ENABLE_AI_FAKE_RESPONSES === 'true') {
  app.get('/gen', strictLimiter, async (req, res) => {
    const amount = parseInt(req.query.amount?.toString() || '1');

    for (let i = 0; i < amount; i++) {
      await generateNewFakeResponse();
      console.log(
        `Populated fake response file with ${i + 1}/${amount} responses.`,
      );
    }

    res.json({ success: true });
  });
}

// Fallback for all other routes
app.use(toolRouter);

startHourlyFakeResponseTask();

export default app;
