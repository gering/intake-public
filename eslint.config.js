import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['node_modules/**', 'coverage/**'] },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: globals.node,
    },
  },
  {
    files: ['public/*.js'],
    languageOptions: { globals: globals.browser },
    rules: { 'no-restricted-globals': ['error', 'process', 'Buffer'] },
  },
];
