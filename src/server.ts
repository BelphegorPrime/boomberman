import dotenv from 'dotenv';
import helmet from 'helmet';
import express from 'express';
import rateLimit from 'express-rate-limit';
import fileRoutes from './routes/files';
import honeypotRoutes from './routes/honeypots';
import metricsRoutes from './routes/metrics';
import { isBanned } from './utils/logger';

dotenv.config();

const app = express();

app.use(helmet());
app.use(express.json());

app.use(rateLimit({
    windowMs: 60_000,
    max: 10
}));

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

app.use('/files', fileRoutes);
app.use('/', honeypotRoutes);
app.use('/metrics', metricsRoutes);

export default app;
