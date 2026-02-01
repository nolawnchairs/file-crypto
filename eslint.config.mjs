import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import { defineConfig } from "eslint/config";
import stylisticPlugin from '@stylistic/eslint-plugin'

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs,ts,mts,cts}"],
    plugins: {
      js,
      '@stylistic': stylisticPlugin
    },
    extends: ["js/recommended"],
    languageOptions: {
      globals: globals.node
    },
    rules: {
      'arrow-parens': 'error',
      'eol-last': 'error',
      'new-parens': 'error',
      'no-console': 'warn',
      'no-multi-spaces': 'error',
      'no-multiple-empty-lines': [
        'error',
        {
          max: 1,
          maxEOF: 0,
          maxBOF: 1,
        },
      ],
      'no-trailing-spaces': 'error',
      'no-var': 'error',
      'object-curly-spacing': ['error', 'always'],
      'prefer-const': [
        'error',
        {
          destructuring: 'any',
        },
      ],
      'prefer-template': 'error',
      'quotes': ['error', 'single'],
      'quote-props': ['error', 'consistent-as-needed'],
      'semi': ['error', 'never'],
      'spaced-comment': ['warn', 'always'],

      // Turn off in favor of TS-ESLint
      'no-unused-vars': 'off',

      // Stylistic ESLint

      '@stylistic/block-spacing': 'error',
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/comma-dangle': [
        'error',
        {
          arrays: 'always-multiline',
          objects: 'always-multiline',
          imports: 'always-multiline',
          enums: 'always',
          exports: 'always-multiline',
          functions: 'never',
        },
      ],
      '@stylistic/indent': [
        'error',
        2,
        {
          SwitchCase: 1,
          FunctionExpression: { parameters: 'first' },
          ignoredNodes: [
            'FunctionExpression > .params[decorators.length > 0]',
            'FunctionExpression > .params > :matches(Decorator, :not(:first-child))',
            'ClassBody.body > PropertyDefinition[decorators.length > 0] > .key',
          ],
        },
      ],
      '@typescript-eslint/no-mixed-enums': 'error',
      '@typescript-eslint/no-base-to-string': 'error',
      '@typescript-eslint/no-loop-func': 'error',
      '@typescript-eslint/no-unnecessary-boolean-literal-compare': 'error',
      '@typescript-eslint/no-unused-vars': 'off', // Turn off in favor of unused-imports
      '@typescript-eslint/return-await': 'error',
      '@typescript-eslint/await-thenable': 'error',
    }
  },
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
])
