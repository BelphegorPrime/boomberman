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

const prompts = [
  'Generate a fake JSON error response intended to confuse automated scraping tools. Include inconsistencies like misaligned keys, invalid values, or weird nesting.',
  'Generate a fake JSON error response that confuses scrapers by using inconsistent key names, wrong data types, and unexpected null or empty values. Example: numeric error codes as strings, error messages nested inside arrays, or missing keys.',
  'Create a JSON error response with weird, unpredictable nesting: error details buried inside arrays and objects with inconsistent key naming and some values replaced by empty arrays or objects. Include boolean values where strings are expected.',
  'Produce a fake JSON error response that contains duplicate keys, contradictory error codes, and mismatched value types (e.g. error code both as a number and a string). The structure should be hard for scrapers to parse.',
  'Generate a confusing JSON error response where error codes randomly switch between strings and numbers, messages include unusual Unicode characters or escaped sequences, and some keys are purposely misspelled or misaligned.',
  'Simulate a malformed JSON error response with misplaced brackets, missing commas, or extra commas, but still parseable by lenient JSON parsers. Include unusual nesting and inconsistent value types.',
  'Generate a JSON error response where error details switch unpredictably between arrays and objects. Some error messages should be arrays of strings, while others are single strings or nested objects with irrelevant keys.',
  'Create a fake JSON error response that uses misleading keys like "statusMessage" for error codes and "errorFlag" for error messages. Include some irrelevant metadata keys with random values.',
  'Produce a JSON error response where keys and values are sometimes swapped (e.g., error codes appear as keys, and the key names appear as values). Nest these swaps inside objects and arrays.',
  'Generate a JSON error response with truncated or partial key names (like "err", "msg", "cd") and partial or corrupted values (like "Faile", "Unkno", 0x00). Introduce inconsistencies in casing and spacing.',
  'Create a JSON error response that contains nested "errors" arrays with unrelated or contradictory error objects inside, some having valid-looking codes, others with nonsense messages or null values.',
  'Generate a JSON error response where key names randomly use different capitalizations and include whitespace or special characters, like "Error Code", "error_Code", or "ERROR-code". Some keys may even be duplicated with different casing.',
  'Produce a JSON error response that includes escaped Unicode characters, backslashes, and newline characters inside error messages, making it confusing for parsers expecting clean strings.',
  'Generate a JSON error response where some error indicators are booleans (true/false), others are null, and some are strings like "false" or "null" — all mixed unpredictably.',
  'Create a JSON error response where error codes and messages are hidden inside unrelated or misleading keys like "metadata", "info", or "debug", buried deeply in the structure.',
  'Generate a JSON error response that includes keys or values hinting at circular references or recursive errors (e.g., "causedBy": "errorCode123" repeated inside nested errors) without causing actual parsing failures.',
];

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

function saveToDisk() {
  try {
    fs.writeFileSync(
      fakeResponeFile,
      cache.map((e) => JSON.stringify(e)).join('\n'),
    );
  } catch (err) {
    console.error('Failed to save fake responses:', err);
  }
}

async function generateNewFakeResponse() {
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

  const randomPrompt = prompts[Math.floor(Math.random() * prompts.length)];

  try {
    const content = await adapter.generateResponse(randomPrompt);
    if (!content) {
      return;
    }

    const entry = { timestamp: new Date().toISOString(), content };
    cache.push(entry);
    saveToDisk();
    console.log('New fake response generated and saved to disk.');
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

async function startHourlyFakeResponseTask() {
  if (!ENABLE_AI) {
    return;
  }

  loadCacheFromDisk();

  setInterval(generateNewFakeResponse, 60 * 60 * 1000);

  if (process.env.AI_PRE_POPULATE_CACHE === 'true') {
    for (let i = 0; i < 20; i++) {
      await generateNewFakeResponse();
      console.log(
        `Pre-populated fake response file with ${i + 1}/20 responses.`,
      );
    }
  } else {
    await generateNewFakeResponse();
  }
}

export { startHourlyFakeResponseTask, getRandomFakeResponse };
