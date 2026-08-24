import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { createOrigin, listStaticRootChildren, normalizeStaticRoot, originView, updateOrigin } from "../src/services/origin-pool-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { SiteRecord } from "../src/types.ts";

let jailRoot: string;
let siteDir: string;
let previousRootDirectory: string;

beforeAll(async () => {
	jailRoot = await mkdtemp(join(tmpdir(), "burrowgate-static-jail-"));
	previousRootDirectory = config.staticSites.rootDirectory;
	config.staticSites.rootDirectory = jailRoot;

	siteDir = join(jailRoot, "my-site");
	await mkdir(siteDir);
	await writeFile(join(siteDir, "index.html"), "<html>ok</html>");
	await writeFile(join(jailRoot, "not-a-directory.txt"), "nope");
	await mkdir(join(siteDir, "nested"));
	await mkdir(join(jailRoot, "no-index"));
});

afterAll(async () => {
	config.staticSites.rootDirectory = previousRootDirectory;
	await rm(jailRoot, { recursive: true, force: true });
});

async function site(): Promise<SiteRecord> {
	return (await createSite({ name: "static test", publicHost: `static-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

describe("normalizeStaticRoot", () => {
	test("accepts a directory inside the jail", () => {
		expect(normalizeStaticRoot("my-site")).toBe(siteDir);
	});

	test("rejects a path that escapes the jail via traversal", () => {
		expect(() => normalizeStaticRoot("../outside")).toThrow("must resolve inside");
	});

	test("rejects an absolute path outside the jail", () => {
		expect(() => normalizeStaticRoot("/etc")).toThrow("must resolve inside");
	});

	test("rejects a path that does not exist", () => {
		expect(() => normalizeStaticRoot("missing-dir")).toThrow("does not exist");
	});

	test("rejects a path that is a file, not a directory", () => {
		expect(() => normalizeStaticRoot("not-a-directory.txt")).toThrow("is not a directory");
	});
});

describe("origin-pool-service static origins", () => {
	test("creates a static origin and exposes staticRoot instead of originUrl", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, { name: "static-origin", originType: "static", staticRoot: "my-site" });
		expect(origin.origin_type).toBe("static");
		expect(origin.origin_url).toBe(siteDir);
		expect(origin.static_index_file).toBe("index.html");

		const view = originView(origin);
		expect(view.originType).toBe("static");
		expect(view.originUrl).toBeNull();
		expect(view.staticRoot).toBe(siteDir);
	});

	test("rejects mTLS on a static origin instead of silently keeping stale credentials", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, { name: "static-no-mtls", originType: "static", staticRoot: "my-site", mtlsEnabled: true });
		expect(origin.mtls_enabled).toBe(0);
	});

	test("switches an origin from proxy to static and back", async () => {
		const s = await site();
		const created = await createOrigin(s.id, { name: "switchable", originUrl: "https://backend.test" });
		expect(created.origin_type).toBe("proxy");

		const toStatic = await updateOrigin(s.id, created.id, { originType: "static", staticRoot: "my-site" });
		expect(toStatic.origin_type).toBe("static");
		expect(toStatic.origin_url).toBe(siteDir);

		const backToProxy = await updateOrigin(s.id, created.id, { originType: "proxy", originUrl: "https://backend2.test" });
		expect(backToProxy.origin_type).toBe("proxy");
		expect(backToProxy.origin_url).toBe("https://backend2.test");
	});

	test("rejects an invalid origin type", async () => {
		const s = await site();
		await expect(createOrigin(s.id, { name: "bad-type", originType: "ftp", originUrl: "https://backend.test" })).rejects.toThrow(
			"Origin type must be proxy or static",
		);
	});
});

describe("listStaticRootChildren", () => {
	test("lists top-level directories, skipping files, with no parent", async () => {
		const listing = await listStaticRootChildren(undefined);
		expect(listing.relativePath).toBe("");
		expect(listing.parentPath).toBeNull();
		const names = listing.entries.map((entry) => entry.name).sort();
		expect(names).toEqual(["my-site", "no-index"]);
		expect(listing.entries.find((entry) => entry.name === "my-site")?.hasIndexFile).toBe(true);
		expect(listing.entries.find((entry) => entry.name === "no-index")?.hasIndexFile).toBe(false);
	});

	test("descends into a subdirectory and reports its parent", async () => {
		const listing = await listStaticRootChildren("my-site");
		expect(listing.relativePath).toBe("my-site");
		expect(listing.parentPath).toBe("");
		expect(listing.entries.map((entry) => entry.name)).toEqual(["nested"]);
	});

	test("rejects a path that escapes the jail", async () => {
		await expect(listStaticRootChildren("../../etc")).rejects.toThrow("must resolve inside");
	});

	test("rejects a path that does not exist", async () => {
		await expect(listStaticRootChildren("missing-dir")).rejects.toThrow("does not exist");
	});
});
