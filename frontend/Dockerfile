# syntax=docker/dockerfile:1

ARG NODE_VERSION=20-alpine

FROM node:${NODE_VERSION} AS base
WORKDIR /app
COPY package.json package-lock.json ./
# Install dependencies separately to leverage Docker layer caching
RUN npm ci
COPY . .

# Development stage used by docker compose for hot reloading
FROM base AS dev
ENV NODE_ENV=development
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]

# Production build stage
FROM base AS build
ENV NODE_ENV=production
RUN npm run build

# Production runtime image served by nginx
FROM nginx:1.27-alpine AS prod
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
