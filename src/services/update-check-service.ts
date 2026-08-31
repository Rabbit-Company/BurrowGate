import { config } from "../config.ts";
import { Logger } from "../logger.ts";
import packageMetadata from "../../package.json" with { type: "json" };

const GITHUB_LATEST_RELEASE_URL = "https://api.github.com/repos/Rabbit-Company/BurrowGate/releases/latest";
const CURRENT_VERSION = packageMetadata.version;

export interface UpdateStatus {
	checkedAt: number | null;
	currentVersion: string;
	latestVersion: string | null;
	updateAvailable: boolean;
	releaseName: string | null;
	releaseNotes: string | null;
	releaseUrl: string | null;
	publishedAt: string | null;
	error: string | null;
}

function compareVersions(a: string, b: string): number {
	const partsA = a.split(".").map((part) => Number.parseInt(part, 10) || 0);
	const partsB = b.split(".").map((part) => Number.parseInt(part, 10) || 0);
	const length = Math.max(partsA.length, partsB.length);
	for (let i = 0; i < length; i++) {
		const diff = (partsA[i] ?? 0) - (partsB[i] ?? 0);
		if (diff !== 0) return diff;
	}
	return 0;
}

class UpdateCheckManager {
	private status: UpdateStatus = {
		checkedAt: null,
		currentVersion: CURRENT_VERSION,
		latestVersion: null,
		updateAvailable: false,
		releaseName: null,
		releaseNotes: null,
		releaseUrl: null,
		publishedAt: null,
		error: null,
	};

	get(): UpdateStatus {
		return this.status;
	}

	start(): void {
		if (!config.updateCheck.enabled) return;
		const timer = setInterval(() => void this.refresh(), config.updateCheck.intervalHours * 3_600_000);
		(timer as unknown as { unref?: () => void }).unref?.();
		void this.refresh();
	}

	async refresh(): Promise<void> {
		try {
			const response = await fetch(GITHUB_LATEST_RELEASE_URL, {
				headers: { accept: "application/vnd.github+json", "user-agent": "BurrowGate-update-check" },
				signal: AbortSignal.timeout(10_000),
			});
			if (!response.ok) throw new Error(`GitHub API returned HTTP ${response.status}`);
			const release = (await response.json()) as {
				tag_name?: string;
				name?: string;
				html_url?: string;
				published_at?: string;
				body?: string;
				draft?: boolean;
				prerelease?: boolean;
			};
			if (release.draft || release.prerelease || !release.tag_name) return;
			const latestVersion = release.tag_name.replace(/^v/i, "");
			this.status = {
				checkedAt: Date.now(),
				currentVersion: CURRENT_VERSION,
				latestVersion,
				updateAvailable: compareVersions(latestVersion, CURRENT_VERSION) > 0,
				releaseName: release.name?.trim() || latestVersion,
				releaseNotes: release.body ?? "",
				releaseUrl: release.html_url ?? `https://github.com/Rabbit-Company/BurrowGate/releases/tag/${release.tag_name}`,
				publishedAt: release.published_at ?? null,
				error: null,
			};
		} catch (error) {
			const message = error instanceof Error ? error.message : "Update check failed";
			Logger.warn("Unable to check for updates", { error: message });
			this.status = { ...this.status, checkedAt: Date.now(), error: message };
		}
	}
}

export const updateCheckManager = new UpdateCheckManager();
