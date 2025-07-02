import { Request, Router } from 'express';
import { logThreat } from '../utils/logger';
import { generateFaultyResponse } from '../utils/generateFaultyResponse';

const honeypots = ['/admin', '/shell', '/login', '/wp-admin', '/.env'];

const router = Router();

export const handleHoneyPot = (req: Request, path = '/') => {
  const ip = req.realIp || 'unknown';
  logThreat('HONEYPOT_HIT', path, ip);
};

const createHoneypotRoute = (path: string) => {
  router.all(path, (req, res) => {
    handleHoneyPot(req, path);
    generateFaultyResponse(res);
  });
};

honeypots.forEach(createHoneypotRoute);

export default router;
