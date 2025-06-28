import dotenv from 'dotenv';
import helmet from 'helmet';
import express, { Router } from 'express';
import fileRoutes from './routes/files';
import honeypotRoutes from './routes/honeypots';
import metricsRoutes from './routes/metrics';
import captchaRouter from './routes/captcha'
import { isBanned } from './utils/logger';
import { tarpit } from './middleware/tarpit';
import { defaultLimiter, strictLimiter } from './middleware/rateLimiter';

dotenv.config();

const app = express();


app.use(helmet());
app.use(express.json());
app.use(defaultLimiter);

// Block banned IPs
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';

    req.realIp = ip;

    if (isBanned(ip)) {
        return res.status(403).send('Your IP has been banned.');
    }

    next();
});

app.use('/public', fileRoutes);
app.use('/tool/tarpit', tarpit, Router());
app.use('/tool/pot', honeypotRoutes);
app.use('/tool/captcha', captchaRouter);
app.use('/metrics', strictLimiter, metricsRoutes);

export default app;
