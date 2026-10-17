import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config.ts";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      restoreMocks: true,
      coverage: {
        provider: "v8",
        include: ["src/**/*.{ts,tsx}"],
        exclude: ["src/main.tsx", "src/api/openapi.d.ts", "src/test/**", "src/**/*.test.{ts,tsx}", "src/vite-env.d.ts"],
        thresholds: { lines: 80, statements: 80, functions: 80, branches: 75 },
        reporter: ["text-summary", "text"],
      },
    },
  }),
);
