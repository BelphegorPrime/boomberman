// rotateFile.ts
import fs from 'fs';
import path from 'path';

export interface RotateFileOptions {
  /** Directory where the file resides */
  dir: string;
  /** Base file name to rotate (e.g., app.log) */
  filename: string;
  /** Retention period in days (default: 7) */
  retentionDays?: number;
  /** Optional prefix for rotated files (defaults to filename without extension) */
  prefix?: string;
}

/**
 * Rotates a file by renaming it with today's date and deleting old rotated files.
 */
export function rotateFile({
  dir,
  filename,
  retentionDays = 7,
  prefix,
}: RotateFileOptions): void {
  const today = new Date().toISOString().split('T')[0];
  const ext = path.extname(filename);
  const base = prefix || path.basename(filename, ext);

  const sourcePath = path.join(dir, filename);
  const rotatedName = `${base}-${today}${ext}`;
  const rotatedPath = path.join(dir, rotatedName);

  // Rotate only if today's rotated file doesn't exist yet
  if (fs.existsSync(sourcePath) && !fs.existsSync(rotatedPath)) {
    fs.renameSync(sourcePath, rotatedPath);
  }

  // Delete old rotated files
  const files = fs.readdirSync(dir);
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  for (const file of files) {
    const match = file.match(
      new RegExp(`^${base}-(\\d{4}-\\d{2}-\\d{2})\\${ext}$`),
    );
    if (match) {
      const date = new Date(match[1]);
      if (!isNaN(date.getTime()) && date.getTime() < cutoff) {
        fs.unlinkSync(path.join(dir, file));
      }
    }
  }
}
