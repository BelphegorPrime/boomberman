import { Router } from 'express';
import path from 'path';
import fs from 'fs';
import { logThreat } from '../utils/logger';

const router = Router();

const publicFolderPath = path.resolve(__dirname, '../../public');

if (!fs.existsSync(publicFolderPath)) {
    console.warn(`[Warning] Public folder does not exist at ${publicFolderPath}`);
    fs.mkdirSync(publicFolderPath, { recursive: true });
}

router.get('/:filename', (req, res) => {
    if (!fs.existsSync(publicFolderPath)) {
        return res.status(404).send('File not found');
    }

    const filePath = path.resolve(publicFolderPath, req.params.filename);
    if (fs.existsSync(filePath)) {
        const ip = req.realIp || 'unknown';
        logThreat('FILE_DOWNLOAD', req.params.filename, ip);
        res.download(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

export default router;
