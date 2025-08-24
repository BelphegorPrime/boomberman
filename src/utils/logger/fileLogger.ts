import fs from 'fs';
import path from 'path';
import schedule from 'node-schedule';
import { ensureDirExistence } from '../ensureDirExistence.js';
import { rotateFile, RotateFileOptions } from '../rotateFile.js';
import { isTest } from '../isTest.js';

if (!isTest) {
  const orig = {
    log: console.log,
    warn: console.warn,
    error: console.error,
  };

  const logFile =
    process.env.LOG_FILE_PATH || path.resolve(process.cwd(), 'data/app.log');
  ensureDirExistence(logFile);

  const rotateFileOptions: RotateFileOptions = {
    dir: path.dirname(logFile),
    filename: path.basename(logFile),
    retentionDays: parseInt(process.env.LOG_RETENTION_DAYS || '7', 10),
  };

  let logStream = fs.createWriteStream(logFile, { flags: 'a' });
  rotateFile(rotateFileOptions);
  schedule.scheduleJob('0 0 * * *', () => {
    rotateFile(rotateFileOptions);
    logStream = fs.createWriteStream(logFile, { flags: 'a' });
  });

  const log = (type: 'log' | 'warn' | 'error', args: unknown[]) => {
    const now = new Date().toISOString();
    const message = `[${now}] [${type.toUpperCase()}] ${args.map(String).join(' ')}\n`;
    logStream.write(message);
  };

  console.log = (...args: unknown[]) => {
    log('log', args);
    orig.log(...args);
  };

  console.warn = (...args: unknown[]) => {
    log('warn', args);
    orig.warn(...args);
  };

  console.error = (...args: unknown[]) => {
    log('error', args);
    orig.error(...args);
  };
}