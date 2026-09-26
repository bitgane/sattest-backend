/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    // Never pick up compiled output — only run tests from source
    testPathIgnorePatterns: ['/node_modules/', '/dist/'],
    // nostr-tools and @noble/* ship as ESM — transform their .js files too
    transformIgnorePatterns: ['node_modules/(?!(@noble|@scure|nostr-tools)/)'],
    transform: {
        '^.+\\.tsx?$': 'ts-jest',
        '^.+\\.js$': ['ts-jest', { tsconfig: { allowJs: true } }],
    },
    // Polyfill Web Crypto API for older Node versions (required by @noble/*)
    setupFiles: ['<rootDir>/jest.setup.js'],
};