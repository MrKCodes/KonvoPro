// Flat ESLint config for the konvo-platform monorepo.
//
// Enforces design.md Appendix A and Requirement 19.6 / 19.11:
//   - TypeScript strict, no `any`, no implicit any
//   - --max-warnings=0 in CI
//
// Per-package configs may extend or override this via their own
// eslint.config.js; this root config covers all .ts / .tsx files.

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.turbo/**',
      '**/*.min.js',
      'legacy/**',
      'e2e/test-results/**',
      'e2e/playwright-report/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx,mts,cts}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    rules: {
      // Requirement 19.11 — no `any` in production source.
      '@typescript-eslint/no-explicit-any': 'error',

      // Defense in depth — non-null assertions silently bypass strict null checks.
      '@typescript-eslint/no-non-null-assertion': 'error',

      // Requirement 19.6 — strict types and no implicit any are enforced by tsc;
      // these surface unused symbols as warnings rather than tsc errors.
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // Reinforce strict typing posture.
      '@typescript-eslint/consistent-type-imports': 'warn',
      '@typescript-eslint/no-unsafe-function-type': 'error',
      '@typescript-eslint/no-empty-object-type': 'error',

      // Disallow leaking debug code into production source.
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-debugger': 'error',
    },
  },
  {
    // Config files and tests are allowed to be a bit looser.
    files: [
      '**/*.config.{js,cjs,mjs,ts}',
      '**/*.test.{ts,tsx}',
      '**/*.spec.{ts,tsx}',
      '**/test/**',
      '**/tests/**',
    ],
    rules: {
      'no-console': 'off',
    },
  },
);
