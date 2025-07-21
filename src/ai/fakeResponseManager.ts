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

const promptCategories = {
  errors: {
    weight: 1,
    prompts: [
      'Generate a fake JSON error response using mismatched key names, random casing, and swapped value types like numbers in strings or vice versa.',
      "Create a malformed error response with misplaced brackets or duplicated keys. Still ensure it's parseable by forgiving parsers.",
      'Produce a confusing JSON error where messages are inside arrays, error codes are booleans, and some keys are misspelled or nonsense.',
      "Construct a recursive-style JSON error response where each 'causedBy' refers to the same or higher-level error code.",
      'Make an error response where some keys are in camelCase, some in snake_case, and others in ALL CAPS or with spaces.',
      "Write a fake error payload with contradictory values, like 'success': true alongside 'errorCode': 500, buried under irrelevant keys.",
      'Simulate a JSON warning message with logical inconsistencies like negative timeout values or future timestamps from 2099.',
      'Create a fake JSON error where some values are corrupted text, keys are partly truncated, and whitespace is randomly injected in field names.',
    ],
  },
  userData: {
    weight: 1,
    prompts: [
      'Invent a JSON payload with plausible keys but unrelated values. Add odd nesting, partial key names, and inconsistent spelling or casing.',
      "Produce a fake JSON that pretends to be valid user data but includes bizarre data types (e.g. 'isAdmin': 'probably'), odd nesting, and contradictory fields.",
      "Construct a fake social media profile in JSON, where fields like 'followers' are negative numbers, bios are arrays, and account dates go backward.",
    ],
  },
  apis: {
    weight: 1,
    prompts: [
      'Generate a fake JSON API response that looks correct but contains subtle flaws: type mismatches, swapped key/value roles, and deeply misplaced data.',
      'Create a JSON document that looks like an online store inventory but mixes prices, ingredients, and error messages inside nested arrays.',
      "Write a JSON object pretending to represent a blog post, but the content is inside 'meta', tags are numbers, and comments are base64 blobs.",
    ],
  },
  telemetry: {
    weight: 1,
    prompts: [
      "Write a fake telemetry payload where metrics like CPU or memory are mixed with philosophical terms like 'consciousnessLevel' or 'karmaLoad'.",
      "Generate a weather API response in JSON where temperature is a string with emojis, windSpeed is an object, and humidity is just 'yes'.",
      'Produce a machine learning model output where confidence scores exceed 100%, predictions are emojis, and classes are nested in nonsense keys.',
    ],
  },
  media: {
    weight: 1,
    prompts: [
      'Generate a JSON chat history where usernames are true/false, messages are missing or nested in arrays, and timestamps defy logic.',
      "Create a JSON news article that’s replaced halfway through with unrelated keys like 'cartItems', 'errorStatus', or 'userAvatarBase64'.",
    ],
  },
  surreal: {
    weight: 1,
    prompts: [
      'Simulate a JSON analytics dashboard response with charts defined by booleans, legends as arrays of nulls, and widgets named after moods.',
      'Fabricate a JSON object that pretends to be a system configuration file, but has keys in Latin or Greek, values as emojis or base64, and randomized structure.',
      'Generate a fake health-tracker JSON payload that mixes steps with sleep logs, water intake as strings, and mood as deeply nested arrays.',
    ],
  },
};

const pickRandomPrompt = () => {
  const expanded = [];

  // Build a weighted list
  for (const [category, data] of Object.entries(promptCategories)) {
    for (let i = 0; i < data.weight; i++) {
      expanded.push({ category, prompts: data.prompts });
    }
  }

  // Pick random category
  const randomCategory = expanded[Math.floor(Math.random() * expanded.length)];

  // Pick random prompt
  const index = Math.floor(Math.random() * randomCategory.prompts.length);
  const prompt = randomCategory.prompts[index];

  return {
    prompt,
    category: randomCategory.category,
  };
};

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

  try {
    const { prompt, category } = pickRandomPrompt();

    const content = await adapter.generateResponse(prompt);
    if (!content) {
      return;
    }

    const entry = {
      timestamp: new Date().toISOString(),
      content,
      category,
      prompt,
    };
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
