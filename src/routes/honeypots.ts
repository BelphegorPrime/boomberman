import { Router } from 'express';
import { logThreat } from '../utils/logger';

const honeypots = ['/admin', '/shell', '/login', '/wp-admin', '/.env'];

const router = Router();

honeypots.forEach(path => {
    router.all(path, (req, res) => {
        const ip = req.realIp || 'unknown';
        logThreat('HONEYPOT_HIT', path, ip);
        res.status(403).send('Access denied');
    });
});

export default router;
