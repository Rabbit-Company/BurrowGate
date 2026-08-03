import { existsSync, statSync } from "node:fs";
import maxmind, { type CountryResponse, type Reader } from "maxmind";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";

let reader: Reader<CountryResponse> | null = null;
let loadError: string | null = null;
let loading: Promise<void> | null = null;

export interface GeoIpStatus {
	enabled: boolean;
	available: boolean;
	databasePath: string;
	databaseModifiedAt: number | null;
	error: string | null;
}

export async function initializeGeoIp(): Promise<void> {
	if (!config.geoip.enabled || reader) return;
	if (loading) return await loading;
	loading = (async () => {
		if (!existsSync(config.geoip.databasePath)) {
			const message = `GeoIP database not found at ${config.geoip.databasePath}`;
			if (loadError !== message) console.warn(`[BurrowGate] ${message}`);
			loadError = message;
			return;
		}
		try {
			reader = await maxmind.open<CountryResponse>(config.geoip.databasePath, {
				cache: { max: config.geoip.cacheEntries },
				watchForUpdates: true,
				watchForUpdatesNonPersistent: true,
				watchForUpdatesHook: () => console.info("[BurrowGate] Reloaded GeoIP database"),
			});
			loadError = null;
			console.info(`[BurrowGate] GeoIP database loaded from ${config.geoip.databasePath}`);
		} catch (error) {
			reader = null;
			const message = error instanceof Error ? error.message : String(error);
			if (loadError !== message) console.error("[BurrowGate] Unable to load GeoIP database", error);
			loadError = message;
		}
	})();
	try {
		await loading;
	} finally {
		loading = null;
	}
}

export function startGeoIpRetry(): void {
	if (!config.geoip.enabled) return;
	const timer = setInterval(() => {
		if (!reader) void initializeGeoIp();
	}, config.geoip.retrySeconds * 1_000);
	(timer as unknown as { unref?: () => void }).unref?.();
}

export function geoIpAvailable(): boolean {
	return reader !== null;
}

export function lookupCountryCode(ip: string): string | null {
	if (!reader || !maxmind.validate(ip)) return null;
	try {
		const response = reader.get(ip);
		const code = response?.country?.iso_code ?? response?.registered_country?.iso_code;
		return typeof code === "string" && /^[A-Z]{2}$/u.test(code) ? code : null;
	} catch {
		return null;
	}
}

export function countryCodeForStorage(ip: string): string | null {
	if (!reader) return null;
	return lookupCountryCode(ip) ?? "ZZ";
}

export function geoIpStatus(): GeoIpStatus {
	let databaseModifiedAt: number | null = null;
	try {
		if (existsSync(config.geoip.databasePath)) databaseModifiedAt = statSync(config.geoip.databasePath).mtimeMs;
	} catch {
		databaseModifiedAt = null;
	}
	return {
		enabled: config.geoip.enabled,
		available: reader !== null,
		databasePath: config.geoip.databasePath,
		databaseModifiedAt,
		error: loadError,
	};
}

export async function backfillGeoIp(): Promise<void> {
	if (!reader || config.geoip.backfillBatchSize <= 0) return;
	const [events, sessions] = await Promise.all([
		repository.eventsMissingCountry(config.geoip.backfillBatchSize),
		repository.sessionsMissingCountry(config.geoip.backfillBatchSize),
	]);
	for (const event of events) {
		await repository.updateEventCountry(event.id, lookupCountryCode(event.ip) ?? "ZZ");
	}
	for (const session of sessions) {
		await repository.updateSessionCountry(session.id, lookupCountryCode(session.initial_ip) ?? "ZZ");
	}
}
