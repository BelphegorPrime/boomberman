import { Router } from 'express';
import { logThreat } from '../utils/logger';

const router = Router();

const fakeQuestions = [
    "What is 3 + 5?",
    "Type the characters: 4hT7L9",
    "Solve: What is the capital of Spain?",
];

router.get('/login', (req, res) => {
    const question = fakeQuestions[Math.floor(Math.random() * fakeQuestions.length)];
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

router.post('/login', (req, res) => {
    const ip = req.realIp || 'unknown';
    logThreat('CAPTCHA', '/login', ip);

    const fakeStatus = [200, 403, 401, 500, 418][Math.floor(Math.random() * 5)];
    res.status(fakeStatus)

    if (Math.random() < 0.2) {
        return res.send("CAPTCHA failed. Try again.");
    }
    return res.send("CAPTCHA verification error. Please reload.");
});

export default router;
