import { Request, Response, Router } from 'express';
import { handleHoneyPot } from './honeypots';
import { tarpit } from '../middleware/tarpit';
import { generateFaultyResponse } from '../utils/generateFaultyResponse';

type TOOL = "tarpit" | "honeyPot" | "captcha"

const toolsMap: Record<TOOL, (req: Request) => any> = {
    tarpit: (req: Request) => { },
    honeyPot: (req: Request) => handleHoneyPot(req, "/"),
    captcha: (req: Request) => { },
}

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
    const toolsQuery = req.query.tools as "string" | undefined;
    if (!toolsQuery) {
        return res.status(400).json({ error: 'Missing tools query parameter' });
    }
    const requestedTools = toolsQuery.split(',').map(t => t.trim()) as TOOL[];

    const invalidTools = requestedTools.filter(t => !(t in toolsMap));
    if (invalidTools.length > 0) {
        return res.status(400).json({ error: `Unknown tools requested: ${invalidTools.join(', ')}` });
    }

    if (requestedTools.includes('tarpit')) {
        tarpit(req, res, () => { });
    }

    await processTools(req, res, requestedTools);

    generateFaultyResponse(res);
});

export default router;
