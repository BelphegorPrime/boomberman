import { Router } from 'express';
import { logThreat } from '../utils/logger/logger.js';
import { delay } from '../utils/delay.js';

const router = Router();

const fakeQuestions = [
  'What is 3 + 5?',
  'Type the characters: 4hT7L9',
  'Solve: What is the capital of Spain?',
];

const redirectTargets = [
  '/404',
  '/not-found',
  '/oops',
  '/secure/portal',
  '/admin/idashboard',
  '/admin/panel',
];

router.get('/login', async (req, res) => {
  const question =
    fakeQuestions[Math.floor(Math.random() * fakeQuestions.length)];

  await delay(1500 + Math.random() * 1500);

  const html = `
        <html>
            <body>
                <h1>Secure Admin Login</h1>
                <form method="POST">
                    <p>CAPTCHA: ${question}</p>
                    <input type="text" name="captcha" />
                    <button type="submit">Verify</button>
                </form>
            </body>
        </html>
    `;
  res.type('html').send(html);
});

router.post('/login', async (req, res) => {
  const ip = req.realIp || 'unknown';
  logThreat('CAPTCHA', '/login', ip);

  await delay(2000 + Math.random() * 2000);

  const redirectUrl =
    redirectTargets[Math.floor(Math.random() * redirectTargets.length)];
  const delaySec = 1 + Math.floor(Math.random() * 4);
  res.setHeader('Refresh', `${delaySec}; URL=${redirectUrl}`);

  const fakeStatus = [200, 403, 401, 500, 418][Math.floor(Math.random() * 5)];
  res.status(fakeStatus);

  const probability = Math.random();
  if (probability < 0.2) {
    return res.send('CAPTCHA failed. Try again.');
  } else if (Math.random() < 0.5) {
    return res.send('CAPTCHA verification error. Please reload.');
  }

  return res.status(200).send(`
        <html>
          <head><title>Verifying...</title></head>
          <body>
            <h3>Verifying your identity...</h3>
            <p>You’ll be redirected shortly.</p>
            <script>
              setTimeout(() => { window.location.href = "${redirectUrl}";}, ${delaySec * 1000});
            </script>
          </body>
        </html>
    `);
});

export default router;
