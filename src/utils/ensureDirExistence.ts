import fs from 'fs';
import path from "node:path";

export function ensureDirExistence(filePath: string) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}