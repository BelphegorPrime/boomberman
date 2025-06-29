import { OllamaAdapter } from './adapters/OllamaAdapter';
import { AIAdapter } from './adapters/AIAdapter';

let adapter: AIAdapter | null = null;

export function getAIAdapter(): AIAdapter {
    if (adapter) return adapter;

    const provider = process.env.AI_PROVIDER || 'ollama';

    switch (provider) {
        case 'ollama':
            adapter = new OllamaAdapter({
                baseUrl: process.env.OLLAMA_URL || 'http://localhost:11434',
                model: process.env.OLLAMA_MODEL || 'llama3.2',
            });
            break;
        default:
            throw new Error(`Unknown AI_PROVIDER: ${provider}`);
    }

    return adapter;
}
