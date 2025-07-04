import { banIP } from './banFile.js';

async function sendWebhookAlert(payload: {
  type: string;
  target: string;
  ip: string;
  timestamp: string;
}) {
  const url = process.env.WEBHOOK_URL;
  if (!url) {
    return;
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      console.error(`Webhook failed: ${res.status} ${res.statusText}`);
    } else {
      console.log(`Webhook alert sent for ${payload.ip}`);
    }
  } catch (err: unknown) {
    console.error('Webhook fetch failed:', (err as Error).message);
  }
}

export async function logThreat(
  type:
    | 'DIRECTORY_TRAVERSAL_ATTEMPT'
    | 'BOT_TOOLKIT_DETECTED'
    | 'CAPTCHA'
    | 'HONEYPOT_HIT'
    | 'FILE_DOWNLOAD',
  target: string,
  ip: string,
) {
  console.log(`${type} from ${ip} -> ${target}`);

  switch (type) {
    case 'CAPTCHA': {
      break;
    }
    case 'BOT_TOOLKIT_DETECTED':
    case 'HONEYPOT_HIT':
    case 'FILE_DOWNLOAD': {
      banIP(ip);
    }
  }

  const timestamp = new Date().toISOString();
  await sendWebhookAlert({ type, target, ip, timestamp });
}
