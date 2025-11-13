# WatchU Frontend

React dashboard for WatchU analytics APIs. Features include:

- Real-time observability views (HTTP timeline, process tree, heuristic alerts)
- Security analysis summaries based on LLM insights

## Getting Started

```bash
npm install
npm run dev
```

Set API URL via `.env` or environment variable:

```bash
VITE_API_BASE_URL="http://localhost:8080/api/v1"
```

## Connecting to the Gateway Service

1. From the repository root start the Gateway backend. Choose one of the following:
   - Native binary (requires Go toolchain and a PostgreSQL instance):
     ```bash
     cd gateway
     make run
     ```
   - Docker Compose (bundles PostgreSQL + gateway):
     ```bash
     cd gateway
     make compose-up
     ```
2. Confirm the API is reachable at `http://localhost:8080/api` (health check: `GET http://localhost:8080/healthz`).
3. In `frontend/.env` (or your shell), set `VITE_API_BASE_URL` to the gateway URL (`http://localhost:8080/api/v1`).
4. Start the frontend dev server:
   ```bash
   npm run dev
   ```
   The app proxies all requests to the configured gateway endpoint.

## Scripts

- `npm run dev` – start Vite dev server
- `npm run build` – run TypeScript checks then create a production bundle via Vite
- `npm run preview` – preview production build
- `npm run lint` – run ESLint with the repository rule set
- `npm run test` – run Vitest

## Project Structure

- `src/App.tsx` – routing and layout shell
- `src/context/SettingsContext.tsx` – shared host/time range settings
- `src/hooks/useAnalytics.ts` – React Query hooks for API access
- `src/pages/` – top-level pages (dashboard, process explorer, heuristic alerts)
- `src/components/` – reusable UI components
- `src/api/` – API client helpers
- `src/types/` – shared API response typings

## Testing

```bash
npm run test
```

Vitest uses JSDOM environment. Add component tests under `src`.
