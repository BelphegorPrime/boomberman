export const isTest = process.env.NODE_ENV === 'test' ||
    process.env.JEST_WORKER_ID !== undefined ||
    process.argv.some(arg => arg.includes('jest')) ||
    process.env.BAN_FILE_PATH?.includes('test/data');