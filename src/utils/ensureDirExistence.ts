import fs from 'fs';
import path from "node:path";

export function ensureDirExistence(filePath: string) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        console.warn(`[Warning] folder does not exist at ${dir}`);
        fs.mkdirSync(dir, { recursive: true });
    }
}