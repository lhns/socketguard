import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  { ignores: ["dist", "src-tauri", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      // Only the classic hook rules. The v7 "compiler" rules (set-state-in-effect etc.) and
      // exhaustive-deps flag the existing load-on-mount pattern in ~6 components; revisit
      // when those components are rewritten.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "off",
    },
  },
  {
    files: ["*.config.{js,ts}"],
    languageOptions: { globals: { ...globals.node } },
  },
);
