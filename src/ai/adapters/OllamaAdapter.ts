import { parseJSON } from '../../utils/parseJSON';
import { AIAdapter } from './AIAdapter';

export class OllamaAdapter implements AIAdapter {
  private baseUrl: string;
  private model: string;

  constructor(config: { baseUrl: string; model: string }) {
    this.baseUrl = config.baseUrl;
    this.model = config.model;
  }

  private async healthCheck() {
    try {
      const res = await fetch(`${this.baseUrl}`);
      const data = await res.text();
      if (data === 'Ollama is running') {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  async generateResponse(
    prompt: string,
  ): Promise<Record<string, unknown> | null> {
    const isRunning = await this.healthCheck();
    if (!isRunning) {
      throw new Error('Ollama is not running');
    }

    try {
      const res = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: this.model,
          prompt,
          stream: false,
          format: 'json',
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to generate response: ${res.statusText}`);
      }

      const data = await res.json();
      const content = data.response?.trim();

      return content ? parseJSON(content) || null : null;
    } catch (err) {
      const error = err as Error;
      console.error('[OllamaAdapter] Error:', error.message);
      throw error;
    }
  }
}
