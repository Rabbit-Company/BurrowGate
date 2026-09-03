import { describe, expect, test } from "bun:test";
import { powSha256Provider } from "../src/challenges/providers/pow-sha256.ts";
import { countLeadingZeroBits, sha256Bytes } from "../src/utils/crypto.ts";

describe("pow-sha256", () => {
	test("accepts a valid low-difficulty proof", async () => {
		const seed = "test-seed";
		let nonce = 0;
		while (countLeadingZeroBits(await sha256Bytes(`${seed}:${nonce}`)) < 8) nonce += 1;
		const result = await powSha256Provider.verify(
			{ flowId: "f", siteId: "s", clientIp: "127.0.0.1", userAgentHash: "u", expiresAt: Date.now() + 1000, attempts: 0, createdAt: Date.now() },
			{ difficulty: 8 },
			{ seed, difficulty: 8 },
			{ nonce: String(nonce) },
		);
		expect(result.success).toBe(true);
	});
});
