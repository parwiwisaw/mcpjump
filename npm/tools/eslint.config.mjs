export default [{
  files: ['**/*.js', '**/*.mjs'],
  languageOptions: {
    globals: { process: 'readonly', console: 'readonly', require: 'readonly', module: 'readonly' },
  },
  rules: {
    'no-unused-vars': 'error',
    'no-undef': 'error',
    'no-empty': 'error',
    'max-lines-per-function': ['error', { max: 60, skipBlankLines: true, skipComments: true }],
  },
}, {
  files: ['**/*.js'],
  languageOptions: { sourceType: 'commonjs' },
}];
