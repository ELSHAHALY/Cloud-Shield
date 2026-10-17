/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  roots: ["<rootDir>/test"],
  transform: { "^.+\\.ts$": ["ts-jest", { tsconfig: "tsconfig.json" }] },
  collectCoverageFrom: ["src/**/*.ts", "!src/types/**", "!src/healthcheck.ts"],
  coverageThreshold: { global: { lines: 90, statements: 90, functions: 90, branches: 85 } },
  coverageReporters: ["text-summary", "text", "lcov"],
  testTimeout: 20000,
  setupFiles: ["<rootDir>/test/setup-env.ts"],
};
