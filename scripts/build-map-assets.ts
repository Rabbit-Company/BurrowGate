import { readFileSync, writeFileSync } from "node:fs";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const source = readFileSync("public/world.svg");

writeFileSync("public/world.svg.gz", gzipSync(source, { level: 9 }));
writeFileSync(
	"public/world.svg.br",
	brotliCompressSync(source, {
		params: {
			[constants.BROTLI_PARAM_QUALITY]: 11,
		},
	}),
);
