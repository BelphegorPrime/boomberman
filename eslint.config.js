import tseslint from 'typescript-eslint';
import eslintRecommended from '@eslint/js';
import prettier from 'eslint-plugin-prettier/recommended';

export default tseslint.config(
  {
    ignores: [
      'node_modules',
      'dist',
      'coverage',
      '.env.test',
      '.env.example',
      'jest.config.js',
      '.prettierrc',
    ],
  },
  eslintRecommended.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
);
