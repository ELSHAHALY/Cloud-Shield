import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist/", "coverage/", "node_modules/", "src/api/openapi.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-non-null-assertion": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      // Equivalent of react/no-danger (eslint-plugin-react does not support ESLint 10):
      // no HTML is ever rendered from data, and no inline style (the CSP forbids it).
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Never render HTML from data (plan D20)." },
        { selector: "JSXAttribute[name.name='style']", message: "Inline styles are blocked by the CSP; use Tailwind classes." },
        { selector: "AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML)$/]", message: "Never assign innerHTML/outerHTML." },
      ],
      "no-restricted-properties": ["error", { object: "localStorage", message: "Tokens and state stay in sessionStorage (plan D20)." }, { object: "window", property: "localStorage", message: "Tokens and state stay in sessionStorage (plan D20)." }],
    },
  },
  { files: ["scripts/**/*.mjs", "*.config.ts"], languageOptions: { globals: { ...globals.node } } },
);
