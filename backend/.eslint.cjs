module.exports = {
  env: {
    node: true,
    es2021: true,
  },
  extends: ['airbnb-base', 'prettier'],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    'no-console': 'off',
    'no-underscore-dangle': 'off',
    'import/no-extraneous-dependencies': 'off',
    'import/prefer-default-export': 'off',
    'prefer-regex-literals': 'off',
    'no-unused-vars': ['error', { argsIgnorePattern: 'next' }],
    // ✅ Allow .js extensions in ESM imports
    'import/extensions': [
      'error',
      'ignorePackages',
      {
        js: 'always',
        mjs: 'always',
      },
    ],

    // ✅ Prevent "Unable to resolve path" false errors
    'import/no-unresolved': ['error', { ignore: ['\\.js$'] }],
  },
  settings: {
    'import/resolver': {
      node: {
        extensions: ['.js', '.mjs', '.json'],
      },
    },
  },
};