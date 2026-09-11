import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default [
  { ignores: ['dist/', 'node_modules/', 'playwright-report/', 'test-results/'] },
  {
    files: ['src/**/*.ts'],
    languageOptions: { globals: globals.node, parser: tseslint.parser },
    rules: js.configs.recommended.rules,
  },
  {
    files: ['bin/**/*.mjs', 'test/**/*.mjs', '*.mjs'],
    languageOptions: { globals: { ...globals.node, ...globals.browser } },
    rules: js.configs.recommended.rules,
  },
];
