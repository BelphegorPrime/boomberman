import fs from 'fs';
import path from 'path';
import { ensureDirExistence } from '../ensureDirExistence.js';

const orig = {
  log: console.log,
  warn: console.warn,
  error: console.error,
};

const logFile =
  process.env.LOG_FILE_PATH || path.resolve(process.cwd(), 'data/app.log');
ensureDirExistence(logFile);

const logStream = fs.createWriteStream(logFile, { flags: 'a' });

const getTimeStamp = (): string => new Date().toISOString();

const log = (type: 'log' | 'warn' | 'error', args: unknown[]) => {
  const message = `[${getTimeStamp()}] [${type.toUpperCase()}] ${args.map(String).join(' ')}\n`;
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
