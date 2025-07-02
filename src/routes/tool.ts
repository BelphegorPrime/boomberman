import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { handleHoneyPot } from './honeypots';
import { tarpit } from '../middleware/tarpit';
import { generateFaultyResponse } from '../utils/generateFaultyResponse';

type TOOL = "tarpit" | "honeyPot" | "captcha"

const toolsMap: Record<TOOL, (req: Request) => any> = {
    tarpit: (req: Request) => { },
    honeyPot: (req: Request) => handleHoneyPot(req, "/"),
    captcha: (req: Request) => { },
}

const toolsSchema = z.string().transform(val => val.split(',').map(t => t.trim())).pipe(z.array(z.enum(["tarpit", "honeyPot", "captcha"])));

const processTools = async (req: Request, res: Response, tools: TOOL[]) => {
    for (const tool of tools) {
        try {
            await toolsMap[tool](req);
        } catch (e) {
        }
    }
};

const router = Router();

router.get('/', async (req, res) => {
    const validationResult = toolsSchema.safeParse(req.query.tools);

    if (!validationResult.success) {
        return res.status(400).json({ error: 'Invalid tools query parameter', issues: validationResult.error.issues });
    }

    const requestedTools = validationResult.data;

    if (requestedTools.includes('tarpit')) {
        tarpit(req, res, () => { });
    }

    await processTools(req, res, requestedTools);

    generateFaultyResponse(res);
});

export default router;
