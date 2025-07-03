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
      'package.json',
      '.prettierrc',
    ],
    rules: {
      '@typescript-eslint/no-explicit-any': [
        'error',
        {
          fixToUnknown: true,
          ignoreRestArgs: false,
        },
      ],
      'no-empty': 'off',
    },
  },
  eslintRecommended.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
);
