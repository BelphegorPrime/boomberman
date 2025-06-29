import fs from 'fs';
import path from 'path';
import { ensureDirExistence } from '../utils/ensureDirExistence';
import { getAIAdapter } from '.';

const ENABLE_AI = process.env.ENABLE_AI_FAKE_RESPONSES === 'true';

const MAX_FILESIZE_BYTES = Number(process.env.MAX_FAKE_RESPONSE_FILESIZE_BYTES || 0);
const fakeResponeFile = process.env.AI_FAKE_RESPONSES_PATH || path.resolve(__dirname, '../../data/fakeResponses.json');
ensureDirExistence(fakeResponeFile);

// In-memory cache to avoid constant disk reads
let cache: { timestamp: string; content: Record<string, any> }[] = [];

function loadCacheFromDisk() {
    try {
        cache = JSON.parse(fs.readFileSync(fakeResponeFile, 'utf-8'));
    } catch (err) {
        console.error('Failed to load fake responses from disk:', err);
    }
}

function saveCacheToDisk() {
    try {
        fs.writeFileSync(fakeResponeFile, JSON.stringify(cache));
    } catch (err) {
        console.error('Failed to save fake responses:', err);
    }
}

async function appendNewFakeResponse() {
    if (!ENABLE_AI) {
        return;
    }

    const stat = fs.statSync(fakeResponeFile);
    if (MAX_FILESIZE_BYTES && stat.size > MAX_FILESIZE_BYTES) {
        console.warn(`[FAKE-RESPONSES] File size too large: ${stat.size} bytes (limit: ${MAX_FILESIZE_BYTES} bytes)`);
        return;
    }

    const adapter = getAIAdapter();
    const prompt = `Generate a fake JSON error response intended to confuse automated scraping tools. Include inconsistencies like misaligned keys, invalid values, or weird nesting.`;

    const content = await adapter.generateResponse(prompt);
    if (!content) {
        return;
    }

    const entry = { timestamp: new Date().toISOString(), content };
    cache.push(entry);

    saveCacheToDisk();
}

function getRandomFakeResponse(): Record<string, any> | null {
    if (cache.length === 0) {
        return null;
    }

    const random = cache[Math.floor(Math.random() * cache.length)];

    return random.content;
}

function startHourlyFakeResponseTask() {
    if (!ENABLE_AI) {
        return;
    }

    loadCacheFromDisk();

    setInterval(appendNewFakeResponse, 60 * 60 * 1000);

    appendNewFakeResponse();
}

export {
    startHourlyFakeResponseTask,
    getRandomFakeResponse,
};
