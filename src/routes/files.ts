import { Router } from 'express';
import path from 'path';
import fs from 'fs';
import { logThreat } from '../utils/logger.js';

const router = Router();

const publicFolderPath = path.resolve(process.cwd(), 'public');

if (!fs.existsSync(publicFolderPath)) {
  console.warn(`[Warning] Public folder does not exist at ${publicFolderPath}`);
  fs.mkdirSync(publicFolderPath, { recursive: true });
}

router.get('/:filename', (req, res) => {
  const filePath = path.resolve(publicFolderPath, req.params.filename);

  // Security: Prevent directory traversal attacks
  if (!filePath.startsWith(publicFolderPath)) {
    logThreat(
      'DIRECTORY_TRAVERSAL_ATTEMPT',
      req.params.filename,
      req.realIp || 'unknown',
    );
    return res.status(403).send('Forbidden');
  }

  if (fs.existsSync(filePath)) {
    const ip = req.realIp || 'unknown';
    logThreat('FILE_DOWNLOAD', req.params.filename, ip);
    res.download(filePath);
  } else {
    res.status(404).send(); // Remove string and send status code only
  }
});

export default router;
