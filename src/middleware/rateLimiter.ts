import rateLimit from 'express-rate-limit';

const baseOptions = {
  windowMs: 60_000,
  max: 10,
  validate: { xForwardedForHeader: false },
};

export const defaultLimiter = rateLimit(baseOptions);

export const strictLimiter = rateLimit({
  ...baseOptions,
  max: 3,
});
