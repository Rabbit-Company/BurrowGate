import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { repository } from "../src/db/repository.ts";
import { createSite, siteView, updateSite } from "../src/services/site-service.ts";

let jailRoot: string;
let siteDir: string;
let otherDir: string;
let previousRootDirectory: string;

beforeAll(async () => {
	jailRoot = await mkdtemp(join(tmpdir(), "burrowgate-site-static-jail-"));
	previousRootDirectory = config.staticSites.rootDirectory;
	config.staticSites.rootDirectory = jailRoot;

	siteDir = join(jailRoot, "blog");
	otherDir = join(jailRoot, "blog-v2");
	await mkdir(siteDir);
	await mkdir(otherDir);
	await writeFile(join(siteDir, "index.html"), "<html>blog</html>");
	await writeFile(join(otherDir, "index.html"), "<html>blog v2</html>");
});

afterAll(async () => {
	config.staticSites.rootDirectory = previousRootDirectory;
	await rm(jailRoot, { recursive: true, force: true });
});

describe("single-step static site creation", () => {
	test("creates a site with a static primary origin", async () => {
		const { site } = await createSite({
			name: "blog",
			publicHost: `blog-${crypto.randomUUID()}.test`,
			originType: "static",
			staticRoot: "blog",
			staticSpaFallback: true,
		});
		expect(site.origin_type).toBe("static");
		expect(site.origin_url).toBe(siteDir);

		const view = siteView(site);
		expect(view.originType).toBe("static");
		expect(view.originUrl).toBeNull();
		expect(view.staticRoot).toBe(siteDir);

		const primary = await repository.primaryOrigin(site.id);
		expect(primary?.origin_type).toBe("static");
		expect(primary?.origin_url).toBe(siteDir);
		expect(primary?.static_spa_fallback).toBe(1);
		expect(primary?.static_index_file).toBe("index.html");
	});

	test("rejects a static root outside the jail at site creation", async () => {
		await expect(createSite({ name: "bad", publicHost: `bad-${crypto.randomUUID()}.test`, originType: "static", staticRoot: "../../etc" })).rejects.toThrow(
			"must resolve inside",
		);
	});

	test("switches an existing proxy site to static and back via updateSite", async () => {
		const { site } = await createSite({ name: "switchable", publicHost: `switchable-${crypto.randomUUID()}.test`, originUrl: "https://backend.test" });
		expect(site.origin_type).toBe("proxy");

		const { site: toStatic } = await updateSite(site.id, { originType: "static", staticRoot: "blog-v2" });
		expect(toStatic.origin_type).toBe("static");
		expect(toStatic.origin_url).toBe(otherDir);
		const staticPrimary = await repository.primaryOrigin(site.id);
		expect(staticPrimary?.origin_type).toBe("static");
		expect(staticPrimary?.origin_url).toBe(otherDir);

		const { site: backToProxy } = await updateSite(site.id, { originType: "proxy", originUrl: "https://backend2.test" });
		expect(backToProxy.origin_type).toBe("proxy");
		expect(backToProxy.origin_url).toBe("https://backend2.test");
		const proxyPrimary = await repository.primaryOrigin(site.id);
		expect(proxyPrimary?.origin_type).toBe("proxy");
		expect(proxyPrimary?.origin_url).toBe("https://backend2.test");
	});

	test("preserves a custom index file and SPA fallback across unrelated updateSite calls", async () => {
		const { site } = await createSite({
			name: "spa",
			publicHost: `spa-${crypto.randomUUID()}.test`,
			originType: "static",
			staticRoot: "blog",
			staticIndexFile: "app.html",
			staticSpaFallback: true,
		});
		let primary = await repository.primaryOrigin(site.id);
		expect(primary?.static_index_file).toBe("app.html");
		expect(primary?.static_spa_fallback).toBe(1);

		// An unrelated field update (name only) must not silently reset the
		// static-only settings back to their defaults.
		await updateSite(site.id, { name: "spa renamed" });
		primary = await repository.primaryOrigin(site.id);
		expect(primary?.static_index_file).toBe("app.html");
		expect(primary?.static_spa_fallback).toBe(1);
	});

	test("editing the index file and SPA fallback from the site (not the origin) endpoint actually changes them", async () => {
		const { site } = await createSite({
			name: "editable",
			publicHost: `editable-${crypto.randomUUID()}.test`,
			originType: "static",
			staticRoot: "blog",
			staticIndexFile: "start.html",
			staticSpaFallback: false,
		});

		// This is what the dashboard's General tab now sends on every save,
		// including edits, since it always shows and submits the real current
		// values (see siteView's primaryOrigin parameter below).
		await updateSite(site.id, {
			originType: "static",
			staticRoot: "blog",
			staticIndexFile: "changed.html",
			staticSpaFallback: true,
		});

		const primary = await repository.primaryOrigin(site.id);
		expect(primary?.static_index_file).toBe("changed.html");
		expect(primary?.static_spa_fallback).toBe(1);
	});

	test("siteView surfaces the primary origin's real index file and SPA fallback when given the origin record", async () => {
		const { site } = await createSite({
			name: "surfaced",
			publicHost: `surfaced-${crypto.randomUUID()}.test`,
			originType: "static",
			staticRoot: "blog",
			staticIndexFile: "custom.html",
			staticSpaFallback: true,
		});
		const primary = await repository.primaryOrigin(site.id);

		// Without the primary origin, the dashboard would only ever see blanks
		// and every save would revert a customized index file / SPA fallback.
		expect(siteView(site).staticIndexFile).toBe("index.html");
		expect(siteView(site).staticSpaFallback).toBe(false);

		expect(siteView(site, primary).staticIndexFile).toBe("custom.html");
		expect(siteView(site, primary).staticSpaFallback).toBe(true);
	});

	test("a site created without originType still defaults to proxy", async () => {
		const { site } = await createSite({ name: "default-proxy", publicHost: `default-proxy-${crypto.randomUUID()}.test`, originUrl: "https://backend3.test" });
		expect(site.origin_type).toBe("proxy");
		expect(siteView(site).originUrl).toBe("https://backend3.test");
	});
});
