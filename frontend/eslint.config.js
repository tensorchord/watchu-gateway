import js from "@eslint/js";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

const reactFlatRecommended = reactPlugin.configs.flat?.recommended ?? {};
const reactFlatJsxRuntime = reactPlugin.configs.flat?.["jsx-runtime"] ?? {};
const reactHooksRecommended = reactHooksPlugin.configs?.recommended ?? { rules: {} };

const tsProjectConfig = {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
        parserOptions: {
            project: "./tsconfig.json",
            tsconfigRootDir: new URL("./", import.meta.url).pathname
        }
    }
};

const reactConfig = {
    files: ["**/*.{tsx,jsx}"],
    plugins: {
        react: reactPlugin,
        "react-hooks": reactHooksPlugin
    },
    settings: {
        react: {
            version: "detect"
        }
    },
    rules: {
        ...(reactFlatRecommended.rules ?? {}),
        ...(reactFlatJsxRuntime.rules ?? {}),
        ...(reactHooksRecommended.rules ?? {})
    }
};

export default tseslint.config(
    {
        ignores: ["dist/**"]
    },
    js.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    tsProjectConfig,
    reactConfig
);
