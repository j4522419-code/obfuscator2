FROM node:20-bookworm-slim

# The bundled official Luau tools are dynamically linked against libstdc++.
RUN apt-get update \
  && apt-get install -y --no-install-recommends libstdc++6 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
# tsx is currently the production launcher, so include devDependencies in this image.
RUN npm ci --include=dev

COPY . .
RUN npm run typecheck \
  && chmod +x tools/luau/luau tools/luau-compile

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
