import js from "@eslint/js";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist/", "coverage/", "node_modules/", "src/types/openapi.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  security.configs.recommended,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      // Object lookups here are over fixed allow-lists; the generic-sink rule
      // is noise for this codebase. Dynamic regexes and child processes stay errors.
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
    },
  },
  {
    files: ["test/**/*.ts", "scripts/**/*.mjs"],
    rules: { "@typescript-eslint/no-explicit-any": "off", "security/detect-non-literal-regexp": "off" },
  },
  { files: ["**/*.js", "**/*.mjs"], languageOptions: { globals: { ...globals.node }, sourceType: "module" } },
  { files: ["jest.config.js"], languageOptions: { sourceType: "commonjs" } },
);
