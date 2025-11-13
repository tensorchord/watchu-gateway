import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

const rootDir = new URL("./", import.meta.url);

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            "@": path.resolve(rootDir.pathname, "src")
        }
    },
    test: {
        environment: "jsdom",
        globals: true,
        setupFiles: "./vitest.setup.ts"
    }
});
