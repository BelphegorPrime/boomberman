import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { ensureDirExistence } from '../utils/ensureDirExistence.js';
import { getAIAdapter } from './index.js';

type CacheEntry = {
  timestamp: string;
  content: Record<string, unknown>;
  category: string;
  prompt: string;
};

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
      "Construct a recursive-style JSON error where each 'causedBy' refers to itself in a circular loop.",
    ],
  },
  userData: {
    weight: 1,
    prompts: [
      'Produce a fake JSON user profile with impossible fields like age: -42, name: {}, and bio: [true, false, null].',
      "Invent user credentials where 'password' is base64, 'email' is a boolean, and roles include emojis.",
      'Simulate a login payload where usernames are random timestamps and session tokens are math expressions.',
    ],
  },
  ecommerce: {
    weight: 1,
    prompts: [
      'Generate a fake JSON cart with product names as emojis, prices nested in stringified arrays, and stock counts that are negative.',
      'Create an order payload where shipping info is randomly nested inside product descriptions, and dates are from different centuries.',
      'Simulate an inventory JSON where SKUs are floating-point numbers and categories are actually hex codes.',
    ],
  },
  media: {
    weight: 1,
    prompts: [
      "Write a JSON structure that mimics a blog post, but has the title inside 'author', paragraphs in 'tags', and timestamps from the future.",
      "Generate an article payload where 'headline' is a boolean, 'body' is an array of product IDs, and 'author' is missing.",
      'Create a fake news response where each section is randomly replaced with weather or stock market fields.',
    ],
  },
  chat: {
    weight: 1,
    prompts: [
      'Generate a JSON conversation where messages contain timestamps as text, users as integers, and threads are randomly cut off mid-key.',
      "Write a chat export with messages embedded in 'metadata', usernames in different languages, and nested responses inside arrays of booleans.",
      "Simulate a group chat where users are duplicated, and messages are split between unrelated keys like 'status' or 'debug'.",
    ],
  },
  telemetry: {
    weight: 1,
    prompts: [
      "Create a JSON payload that looks like telemetry but includes fields like 'batteryFeeling': 'anxious', and temperature in emojis.",
      'Simulate logs from a device where sensor names are reversed strings, values are in poems, and all timestamps are identical.',
      "Write fake device data with fields named 'blorpFactor', 'signalGhost', and 'isReallyConnected' set to 'who knows?'.",
    ],
  },
  apis: {
    weight: 1,
    prompts: [
      'Create a JSON response that looks like a weather API but delivers user profiles instead — keys are weather terms, values are accounts.',
      "Simulate a REST response where headers are nested inside the body and the body has a key named 'thisShouldntBeHere'.",
      'Design an API payload where endpoints describe entirely different data domains like chat messages or inventory, all in one object.',
    ],
  },
  mlModels: {
    weight: 1,
    prompts: [
      'Generate a fake AI prediction JSON where confidence is 133.7%, labels are jokes, and results reference TV shows.',
      "Simulate ML output with nested vectors of nonsense strings, 'classification': 'yesNoMaybe', and impossible probability math.",
      "Create a model result where the 'embedding' is a Shakespearean quote and each field pretends to be technical but isn't.",
    ],
  },
  surreal: {
    weight: 1,
    prompts: [
      "Construct a dreamlike JSON object with keys like 'existence', 'skyState', and values that change shape between requests.",
      'Simulate a data payload where field names are philosophical concepts and values are emojis or reversed quotes.',
      'Generate a surreal JSON structure where arrays loop in on themselves and strings seem self-aware.',
    ],
  },
  misleadingMeta: {
    weight: 1,
    prompts: [
      "Create a fake config file where the version is 'unreal', paths are haikus, and 'enabled' is represented as Schrödinger's cat.",
      'Generate a JSON system config where every field contradicts another and some settings seem to enable time travel.',
      "Simulate an app manifest with fields like 'compiledFromDream': true, 'uiFeel': 'sticky', and 'license': '???'.",
    ],
  },
  forms: {
    weight: 1,
    prompts: [
      'Create a fake JSON form submission where names are numbers, emails contain emojis, and consent is given via poem.',
      'Simulate a survey response where answers are arrays of booleans, questions are missing, and the structure collapses mid-response.',
      'Generate a contact form submission with duplicated fields, conflicting data types, and encoded fragments in base64.',
    ],
  },
  finance: {
    weight: 1,
    prompts: [
      'Simulate a bank statement where all transactions are in fictional currencies, amounts are emojis, and totals don’t add up.',
      'Create a fake investment JSON where shares are strings, timestamps are hex, and stock tickers are Shakespearean.',
      'Write a transaction history where each entry is formatted differently, and some amounts are deeply nested arrays.',
    ],
  },
  location: {
    weight: 1,
    prompts: [
      'Generate a GPS log where lat/lng are reversed, some coordinates are inside strings, and others are buried in metaphors.',
      'Create a fake location payload with countries as object keys and cities as timestamps.',
      'Simulate a map route JSON where waypoints have emotional states and travel time is measured in riddles.',
    ],
  },
  auth: {
    weight: 1,
    prompts: [
      'Create a fake JSON auth token that changes structure every time, with half of the fields base64 and half hex.',
      'Simulate a login session payload where tokens are booleans, roles are numbers, and sessionID is repeated 3 times.',
      'Generate an OAuth-like payload where fields are misspelled and some scopes are just animals.',
    ],
  },
  music: {
    weight: 1,
    prompts: [
      'Create a JSON music playlist where song titles are timestamps, durations are coordinates, and artists are boolean values.',
      'Simulate an audio track JSON where the waveform is a poem and genres are replaced with weather conditions.',
      'Generate a JSON album metadata structure where every field is either missing or overexplained.',
    ],
  },
  gaming: {
    weight: 1,
    prompts: [
      'Generate a player stats payload where levels go backward, XP is negative, and character names are system errors.',
      "Create a fake game state save file in JSON with keys like 'lastEmotion', 'cheatCodeList', and 'totalBugsUnlocked'.",
      'Simulate a leaderboard JSON where some scores are base64, names are swapped with avatars, and positions are out of order.',
    ],
  },
  iot: {
    weight: 1,
    prompts: [
      'Simulate a smart home payload where devices send back emotional states and uptime is recorded in poetry.',
      "Create a JSON object representing a fridge's contents with items that change type mid-list and temperatures measured in concepts.",
      "Generate a smart sensor log where all readings are strings like 'beep', 'zzz', or 'help'.",
    ],
  },
  analytics: {
    weight: 1,
    prompts: [
      'Generate a JSON analytics snapshot with null metrics, inverted funnels, and chart legends made of nonsense words.',
      'Simulate a report payload where user engagement is measured in philosophical units and every field is named ambiguously.',
      "Create a dashboard data object where widgets track emotions, time spent is a color, and bounce rate is '42'.",
    ],
  },
  aiPersona: {
    weight: 1,
    prompts: [
      'Create a fake AI persona definition where traits are random adjectives, goals are undefined, and ethics policies are reversed.',
      'Simulate an AI identity in JSON where personality values are boolean and likes/dislikes are contradictory arrays.',
      'Generate an AI character sheet where every stat is misaligned, intentions are nested deeply, and alignment is missing.',
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
const cache: CacheEntry[] = [];

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

export async function generateNewFakeResponse() {
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

    const entry: CacheEntry = {
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

  if (process.env.NODE_ENV !== 'test') {
    setInterval(generateNewFakeResponse, 60 * 60 * 1000);
  }

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
