FROM oven/bun:1.4

USER root
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates openssl libcap2-bin nftables \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN bun install --production
COPY . .

RUN mkdir -p /app/data \
	&& chown -R bun:bun /app \
	&& setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(command -v bun)")" \
	&& setcap 'cap_net_admin=+ep' "$(readlink -f "$(command -v nft)")"

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e 'const response = await fetch("http://127.0.0.1/_burrowgate/health"); if (!response.ok) process.exit(1)'

CMD ["bun", "src/index.ts"]