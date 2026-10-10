import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      // Unused parameters that name what an interface passes in are kept, marked with "_".
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
];
