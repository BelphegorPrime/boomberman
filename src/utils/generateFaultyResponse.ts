import { Response } from "express";
import { getRandomFakeResponse } from "../ai/fakeResponseManager";
import { corruptJsonString } from "./corruptJsonString";
import zlib from 'zlib';
import fs from "fs";
import path from "path";
import { log } from "./logger";

const publicFolderPath = path.resolve(__dirname, '../../public');

if (!fs.existsSync(publicFolderPath)) {
    console.warn(`[Warning] Public folder does not exist at ${publicFolderPath}`);
    fs.mkdirSync(publicFolderPath, { recursive: true });
}

function findLargestGzFile(dir: string): string | null {
    let largestFile: string | null = null;
    let largestSize = 0;

    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
            const candidate = findLargestGzFile(fullPath);
            if (candidate) {
                const size = fs.statSync(candidate).size;
                if (size > largestSize) {
                    largestSize = size;
                    largestFile = candidate;
                }
            }
        } else if (entry.isFile() && entry.name.endsWith('.gz')) {
            const size = fs.statSync(fullPath).size;
            if (size > largestSize) {
                largestSize = size;
                largestFile = fullPath;
            }
        }
    }

    return largestFile;
}

function gzipAndSend(res: Response, body: string | Buffer, status = 200, contentType = 'text/plain', disposition?: string) {
    zlib.gzip(body, (err, compressed) => {
        if (err) {
            res.status(500).send('Compression failed');
        } else {
            res
                .status(status)
                .setHeader('Content-Encoding', 'gzip')
                .setHeader('Content-Type', contentType)
                .setHeader('Content-Length', compressed.length)

            if (disposition) {
                res.setHeader('Content-Disposition', disposition)
            }

            res.send(compressed);
        }
    });
}

export function generateFaultyResponse(res: Response) {
    const variants = ['teapot', 'gibberish', 'malformedJson', 'largePayload', 'boom'];
    const choice = variants[Math.floor(Math.random() * variants.length)];

    switch (choice) {
        case 'teapot': {
            log(`[TEAPOT] served`);
            gzipAndSend(res, "I'm a teapot. 🍵", 418)
            break;
        }

        case 'gibberish': {
            const fakeJson = getRandomFakeResponse();
            log(`[GIBBERISH] served`);
            gzipAndSend(res, JSON.stringify(fakeJson || {}), 200, 'application/json')
            break;
        }

        case 'malformedJson': {
            const fakeJson = getRandomFakeResponse();
            const corrupted = fakeJson ?
                corruptJsonString(JSON.stringify(fakeJson)) :
                '{"message": "Oops", "incomplete": true,, }';

            log(`[MALFORMED_JSON] served`);
            gzipAndSend(res, corrupted, 200, 'application/json')
            break;
        }

        case 'largePayload': {
            const lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
            const hugePayload = lorem.repeat(200_000); // ~10MB

            log(`[LARGE_PAYLOAD] served`);
            gzipAndSend(res, hugePayload, 200)
            break;
        }

        case 'boom': {
            const gzPath = findLargestGzFile(publicFolderPath);
            if (gzPath && fs.existsSync(gzPath)) {
                const stat = fs.statSync(gzPath);
                log(`[BOOM] Serving file: ${gzPath} (${(stat.size / 1024).toFixed(2)} KB)`);
                res
                    .status(200)
                    .setHeader('Content-Encoding', 'gzip')
                    .setHeader('Content-Type', 'application/octet-stream')
                    .setHeader('Content-Disposition', `attachment; filename="${path.basename(gzPath)}"`)
                    .setHeader('Content-Length', stat.size);

                const readStream = fs.createReadStream(gzPath);
                return readStream.pipe(res);
            } else {

                const payload = 'A'.repeat(100_000_000); // 100 MB of repeating character
                const buffer = Buffer.from(payload, 'utf-8');

                log('[BOOM] No .gz file found — using fallback compressed payload');
                gzipAndSend(res, buffer, 200, 'application/octet-stream', 'attachment; filename="data.gz"')
            }
            break;
        }

    }
}
