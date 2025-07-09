import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { handleHoneyPot } from './honeypots.js';
import { tarpit } from '../middleware/tarpit.js';
import {
  Choice,
  generateFaultyResponse,
} from '../utils/generateFaultyResponse.js';

type TOOL = 'tarpit' | 'honeyPot' | 'captcha';

const noop = () => { };

const toolsMap: Record<TOOL, (req: Request) => unknown> = {
  tarpit: noop,
  honeyPot: (req: Request) => handleHoneyPot(req, '/'),
  captcha: noop,
};

const allTools: TOOL[] = ['tarpit', 'honeyPot', 'captcha'];
const toolsSchema = z
  .string()
  .transform((val) => val.split(',').map((t) => t.trim()))
  .pipe(z.array(z.enum(['tarpit', 'honeyPot', 'captcha'])));

const choiceSchema = z
  .string()
  .transform((val) => val.split(',').map((t) => t.trim()))
  .pipe(
    z.array(
      z.enum(['teapot', 'gibberish', 'malformedJson', 'largePayload', 'boom']),
    ),
  );

const processTools = async (req: Request, res: Response, tools: TOOL[]) => {
  for (const tool of tools) {
    try {
      await toolsMap[tool](req);
    } catch (error) {
      console.error(`Error processing tool ${tool}:`, error);
    }
  }
};

const router = Router();

router.use(async (req, res) => {
  const validationResult = toolsSchema.safeParse(req.query.tools);

  let requestedTools: TOOL[] = allTools;
  if (validationResult.success) {
    requestedTools = validationResult.data;
  }

  const choicesValidationResult = choiceSchema.safeParse(req.query.choices);
  let choices: Choice[] | undefined = undefined;
  if (choicesValidationResult.success) {
    choices = choicesValidationResult.data;
  }

  if (requestedTools.includes('tarpit')) {
    tarpit(req, res, noop);
  }

  await processTools(req, res, requestedTools);

  generateFaultyResponse(res, choices);
});

export default router;
