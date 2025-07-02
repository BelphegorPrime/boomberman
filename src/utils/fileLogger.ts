import fs from 'fs';
import path from 'path';
import { ensureDirExistence } from './ensureDirExistence';

const orig = {
    log: console.log,
    warn: console.warn,
    error: console.error
}

const logFile = process.env.LOG_FILE_PATH || path.resolve(__dirname, '../../data/app.log');
ensureDirExistence(logFile);

const logStream = fs.createWriteStream(logFile, { flags: 'a' });

const getTimeStamp = (): string => new Date().toISOString()

const format = (type: string, args: any[]): string =>
    `[${getTimeStamp()}] [${type.toUpperCase()}] ${args.map(String).join(' ')}\n`

console.log = (...args: any[]) => {
    logStream.write(format('log', args));
    orig.log(...args);
};

console.warn = (...args: any[]) => {
    logStream.write(format('warn', args));
    orig.warn(...args);
};

console.error = (...args: any[]) => {
    logStream.write(format('error', args));
    orig.error(...args);
};
