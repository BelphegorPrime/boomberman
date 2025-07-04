import { Router } from 'express';
import fs from 'fs';
import path from 'path';

const router = Router();

router.get('/', (req, res) => {
  const logPath =
    process.env.LOG_FILE_PATH || path.resolve(process.cwd(), 'logs/app.log');

  if (fs.existsSync(logPath)) {
    const content = fs.readFileSync(logPath, 'utf-8');
    res.type('text/plain').send(content);
  } else {
    res.send('No metrics yet');
  }
});

export default router;
