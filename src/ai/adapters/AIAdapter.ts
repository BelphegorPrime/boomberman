export interface AIAdapter {
  generateResponse(prompt: string): Promise<Record<string, unknown> | null>;
}
