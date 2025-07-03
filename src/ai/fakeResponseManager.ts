import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { ensureDirExistence } from '../utils/ensureDirExistence.js';
import { getAIAdapter } from './index.js';

const ENABLE_AI = process.env.ENABLE_AI_FAKE_RESPONSES === 'true';

const MAX_FILESIZE_BYTES = Number(
  process.env.MAX_FAKE_RESPONSE_FILESIZE_BYTES || 5000,
);
const fakeResponeFile =
  process.env.AI_FAKE_RESPONSES_PATH ||
  path.resolve(process.cwd(), 'data/fakeResponses.jsonl');
ensureDirExistence(fakeResponeFile);

// In-memory cache to avoid constant disk reads
const cache: { timestamp: string; content: Record<string, unknown> }[] = [];

function loadCacheFromDisk() {
  if (!fs.existsSync(fakeResponeFile)) {
    return;
  }

  const fileStream = fs.createReadStream(fakeResponeFile);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  rl.on('line', (line) => {
    try {
      cache.push(JSON.parse(line));
    } catch (err) {
      console.error('Failed to parse fake response line:', err);
    }
  });

  rl.on('close', () => {
    console.log('Finished loading fake responses from disk.');
  });
}

function appendToDisk(entry: {
  timestamp: string;
  content: Record<string, unknown>;
}) {
  try {
    fs.appendFileSync(fakeResponeFile, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('Failed to save fake responses:', err);
  }
}

async function appendNewFakeResponse() {
  if (!ENABLE_AI) {
    return;
  }

  try {
    const stat = fs.statSync(fakeResponeFile);
    if (MAX_FILESIZE_BYTES && stat.size > MAX_FILESIZE_BYTES) {
      console.warn(
        `[FAKE-RESPONSES] File size too large: ${stat.size} bytes (limit: ${MAX_FILESIZE_BYTES} bytes)`,
      );
      return;
    }
  } catch {
    // File might not exist yet, which is fine
  }

  const adapter = getAIAdapter();
  const prompt = `Generate a fake JSON error response intended to confuse automated scraping tools. Include inconsistencies like misaligned keys, invalid values, or weird nesting.`;

  try {
    const content = await adapter.generateResponse(prompt);
    if (!content) {
      return;
    }

    const entry = { timestamp: new Date().toISOString(), content };
    cache.push(entry);
    appendToDisk(entry);
  } catch (error) {
    console.error('Failed to generate or save fake response:', error);
  }
}

function getRandomFakeResponse(): Record<string, unknown> | null {
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

export { startHourlyFakeResponseTask, getRandomFakeResponse };
