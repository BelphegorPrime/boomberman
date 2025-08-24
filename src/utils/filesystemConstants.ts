
import { fileURLToPath } from 'url';
import path from 'path';

// Get the current file's directory
export const filename = fileURLToPath(import.meta.url);
export const dirname = path.dirname(filename);