/**
 * Single source of truth for the suite list, shared by run-all.ts (which
 * suite to import and what result filename to write) and compare.ts (which
 * filename suffixes count as a known suite when splitting a results
 * filename back into its `<version>-<platform>-<arch>` prefix).
 */
export interface SuiteDescriptor {
	/** Matches the JSON filename suffix: `<prefix>-<slug>.json`. */
	slug: string;
	file: string;
	/** Short keyword accepted by `bun bench/run-all.ts <tag>` filters. */
	tag: string;
}

export const SUITES: SuiteDescriptor[] = [
	{ slug: "01-http-serve", file: "01-http-serve.bench.ts", tag: "http" },
	{ slug: "02-fetch-proxy", file: "02-fetch-proxy.bench.ts", tag: "fetch" },
	{ slug: "03-tcp-stream", file: "03-tcp-stream.bench.ts", tag: "tcp" },
	{ slug: "04-udp-socket", file: "04-udp-socket.bench.ts", tag: "udp" },
	{ slug: "05-websocket", file: "05-websocket.bench.ts", tag: "websocket" },
	{ slug: "06-tls-handshake", file: "06-tls-handshake.bench.ts", tag: "tls" },
	{ slug: "07-password-hash", file: "07-password-hash.bench.ts", tag: "password" },
	{ slug: "08-file-io", file: "08-file-io.bench.ts", tag: "file" },
	{ slug: "09-sqlite", file: "09-sqlite.bench.ts", tag: "sqlite" },
	{ slug: "10-compression", file: "10-compression.bench.ts", tag: "compression" },
];
