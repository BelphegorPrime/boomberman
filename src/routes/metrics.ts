import { Router } from 'express';
import fs from 'fs';
import path from 'path';

const router = Router();

router.get('/', (req, res) => {
  const logPath = path.resolve(__dirname, '../../logs/events.log');
  if (fs.existsSync(logPath)) {
    const content = fs.readFileSync(logPath, 'utf-8');
    res.type('text/plain').send(content);
  } else {
    res.send('No metrics yet');
  }
});

export default router;
