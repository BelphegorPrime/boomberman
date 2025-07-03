import 'dotenv/config';
import './utils/fileLogger.js';
import helmet from 'helmet';
import express, { Router } from 'express';
import fileRoutes from './routes/files.js';
import honeypotRoutes from './routes/honeypots.js';
import metricsRoutes from './routes/metrics.js';
import captchaRouter from './routes/captcha.js';
import toolRouter from './routes/tool.js';
import { isBanned, logThreat } from './utils/logger.js';
import { tarpit } from './middleware/tarpit.js';
import { defaultLimiter, strictLimiter } from './middleware/rateLimiter.js';
import { generateFaultyResponse } from './utils/generateFaultyResponse.js';
import { startHourlyFakeResponseTask } from './ai/fakeResponseManager.js';
import { isKnownBot } from './utils/isKnownBot.js';

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

  next();
});

app.use((req, res, next) => {
  const ua = req.headers['user-agent'] || '';

  if (isKnownBot(ua)) {
    logThreat('BOT_TOOLKIT_DETECTED', req.path, ua);
    generateFaultyResponse(res);
  } else {
    next();
  }
});

app.use('/public', fileRoutes);
app.use('/tool/tarpit', tarpit, Router());
app.use('/tool/pot', honeypotRoutes);
app.use('/tool/captcha', captchaRouter);
app.use('/metrics', strictLimiter, metricsRoutes);

// Fallback for all other routes
app.use(toolRouter);

startHourlyFakeResponseTask();

export default app;
