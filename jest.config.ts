import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { useESM: true }],
  },
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  verbose: true,
  collectCoverageFrom: ['./src/**/*.ts'],
  coverageDirectory: './coverage',
  testMatch: ['**/test/**/*.test.ts'],
  forceExit: true,
  detectOpenHandles: true,
};

export default config;
