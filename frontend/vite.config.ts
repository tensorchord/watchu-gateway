import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const rootDir = new URL("./", import.meta.url);

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, rootDir.pathname, "VITE_");

    return {
        plugins: [react()],
        resolve: {
            alias: {
                "@": path.resolve(rootDir.pathname, "src")
            }
        },
        server: {
            port: Number(env.VITE_DEV_SERVER_PORT ?? 5173)
        }
    };
});
