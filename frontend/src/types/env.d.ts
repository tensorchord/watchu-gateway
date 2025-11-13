interface ImportMetaEnv {
    readonly VITE_API_BASE_URL?: string;
    readonly VITE_DEV_SERVER_PORT?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
