import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default defineConfig(
  { ignores: ['node_modules/**', 'public/client.js', 'public/client.js.map', 'dist/**'] },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
        Bun: 'readonly',
      },
      parserOptions: {
        projectService: true
      }
    },
  },
  {
    files: ['public/**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
);
