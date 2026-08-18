import { existsSync, statSync } from "node:fs";
import maxmind, { type AsnResponse, type CountryResponse, type Reader } from "maxmind";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { isPrivateIp } from "../utils/ip.ts";

export const PRIVATE_COUNTRY_CODE = "XX";
export const UNKNOWN_COUNTRY_CODE = "ZZ";

export interface AsnLookup {
	asn: number;
	org: string;
}

let reader: Reader<CountryResponse> | null = null;
let loadError: string | null = null;
let loading: Promise<void> | null = null;

let asnReader: Reader<AsnResponse> | null = null;
let asnLoadError: string | null = null;
let asnLoading: Promise<void> | null = null;

export interface DatabaseStatus {
	enabled: boolean;
	available: boolean;
	databasePath: string;
	databaseModifiedAt: number | null;
	error: string | null;
}

export interface GeoIpStatus extends DatabaseStatus {
	asn: DatabaseStatus;
}

export async function initializeGeoIp(): Promise<void> {
	if (!config.geoip.enabled || reader) return;
	if (loading) return await loading;
	loading = (async () => {
		if (!existsSync(config.geoip.databasePath)) {
			const message = `GeoIP database not found at ${config.geoip.databasePath}`;
			if (loadError !== message) Logger.warn(`[BurrowGate] ${message}`);
			loadError = message;
			return;
		}
		try {
			reader = await maxmind.open<CountryResponse>(config.geoip.databasePath, {
				cache: { max: config.geoip.cacheEntries },
				watchForUpdates: true,
				watchForUpdatesNonPersistent: true,
				watchForUpdatesHook: () => Logger.info("[BurrowGate] Reloaded GeoIP database"),
			});
			loadError = null;
			Logger.info(`[BurrowGate] GeoIP database loaded from ${config.geoip.databasePath}`);
		} catch (error) {
			reader = null;
			const message = error instanceof Error ? error.message : String(error);
			if (loadError !== message) Logger.error("[BurrowGate] Unable to load GeoIP database", { error });
			loadError = message;
		}
	})();
	try {
		await loading;
	} finally {
		loading = null;
	}
}

export async function initializeAsnGeoIp(): Promise<void> {
	if (!config.geoip.asnEnabled || asnReader) return;
	if (asnLoading) return await asnLoading;
	asnLoading = (async () => {
		if (!existsSync(config.geoip.asnDatabasePath)) {
			const message = `GeoIP ASN database not found at ${config.geoip.asnDatabasePath}`;
			if (asnLoadError !== message) Logger.warn(`[BurrowGate] ${message}`);
			asnLoadError = message;
			return;
		}
		try {
			asnReader = await maxmind.open<AsnResponse>(config.geoip.asnDatabasePath, {
				cache: { max: config.geoip.cacheEntries },
				watchForUpdates: true,
				watchForUpdatesNonPersistent: true,
				watchForUpdatesHook: () => Logger.info("[BurrowGate] Reloaded GeoIP ASN database"),
			});
			asnLoadError = null;
			Logger.info(`[BurrowGate] GeoIP ASN database loaded from ${config.geoip.asnDatabasePath}`);
		} catch (error) {
			asnReader = null;
			const message = error instanceof Error ? error.message : String(error);
			if (asnLoadError !== message) Logger.error("[BurrowGate] Unable to load GeoIP ASN database", { error });
			asnLoadError = message;
		}
	})();
	try {
		await asnLoading;
	} finally {
		asnLoading = null;
	}
}

export function startGeoIpRetry(): void {
	if (config.geoip.enabled) {
		const timer = setInterval(() => {
			if (!reader) void initializeGeoIp();
		}, config.geoip.retrySeconds * 1_000);
		(timer as unknown as { unref?: () => void }).unref?.();
	}
	if (config.geoip.asnEnabled) {
		const timer = setInterval(() => {
			if (!asnReader) void initializeAsnGeoIp();
		}, config.geoip.retrySeconds * 1_000);
		(timer as unknown as { unref?: () => void }).unref?.();
	}
}

export function geoIpAvailable(): boolean {
	return reader !== null;
}

export function asnGeoIpAvailable(): boolean {
	return asnReader !== null;
}

export function lookupCountryCode(ip: string): string | null {
	if (isPrivateIp(ip)) return PRIVATE_COUNTRY_CODE;
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
	if (isPrivateIp(ip)) return PRIVATE_COUNTRY_CODE;
	if (!reader) return null;
	return lookupCountryCode(ip) ?? UNKNOWN_COUNTRY_CODE;
}

/** No real ASN is ever this value (0 is reserved/unallocated), so it doubles as the "no ASN" sentinel for storage, the same way country codes use `XX`/`ZZ`. */
export const NO_ASN = 0;

/** Looks up the ASN for a public IP. Private/local addresses have no ASN, so this always returns `null` for them. */
export function lookupAsn(ip: string): AsnLookup | null {
	if (isPrivateIp(ip)) return null;
	if (!asnReader || !maxmind.validate(ip)) return null;
	try {
		const response = asnReader.get(ip);
		const asn = response?.autonomous_system_number;
		const org = response?.autonomous_system_organization;
		return typeof asn === "number" && typeof org === "string" ? { asn, org } : null;
	} catch {
		return null;
	}
}

/**
 * Same as {@link lookupAsn}, but always resolves to a value once an ASN reader is loaded
 * (`NO_ASN` for private addresses or an unresolvable public one), the same way
 * `countryCodeForStorage` never leaves a loaded reader's rows as `null`. This keeps
 * backfill batches from repeatedly re-selecting rows that can never resolve to a real ASN.
 * Only returns `{ asn: null, org: null }` when no ASN database is loaded at all.
 */
export function asnForStorage(ip: string): { asn: number | null; org: string | null } {
	if (isPrivateIp(ip)) return { asn: NO_ASN, org: "Private network" };
	if (!asnReader) return { asn: null, org: null };
	const lookup = lookupAsn(ip);
	return lookup ? { asn: lookup.asn, org: lookup.org } : { asn: NO_ASN, org: "Unknown" };
}

export function geoIpStatus(): GeoIpStatus {
	let databaseModifiedAt: number | null = null;
	try {
		if (existsSync(config.geoip.databasePath)) databaseModifiedAt = statSync(config.geoip.databasePath).mtimeMs;
	} catch {
		databaseModifiedAt = null;
	}
	let asnDatabaseModifiedAt: number | null = null;
	try {
		if (existsSync(config.geoip.asnDatabasePath)) asnDatabaseModifiedAt = statSync(config.geoip.asnDatabasePath).mtimeMs;
	} catch {
		asnDatabaseModifiedAt = null;
	}
	return {
		enabled: config.geoip.enabled,
		available: reader !== null,
		databasePath: config.geoip.databasePath,
		databaseModifiedAt,
		error: loadError,
		asn: {
			enabled: config.geoip.asnEnabled,
			available: asnReader !== null,
			databasePath: config.geoip.asnDatabasePath,
			databaseModifiedAt: asnDatabaseModifiedAt,
			error: asnLoadError,
		},
	};
}

export async function backfillGeoIp(): Promise<void> {
	if (reader && config.geoip.backfillBatchSize > 0) {
		const [events, sessions] = await Promise.all([
			repository.eventsMissingCountry(config.geoip.backfillBatchSize),
			repository.sessionsMissingCountry(config.geoip.backfillBatchSize),
		]);
		for (const event of events) {
			await repository.updateEventCountry(event.id, lookupCountryCode(event.ip) ?? UNKNOWN_COUNTRY_CODE);
		}
		for (const session of sessions) {
			await repository.updateSessionCountry(session.id, lookupCountryCode(session.initial_ip) ?? UNKNOWN_COUNTRY_CODE);
		}
	}
	if (asnReader && config.geoip.backfillBatchSize > 0) {
		const [events, sessions] = await Promise.all([
			repository.eventsMissingAsn(config.geoip.backfillBatchSize),
			repository.sessionsMissingAsn(config.geoip.backfillBatchSize),
		]);
		for (const event of events) {
			const { asn, org } = asnForStorage(event.ip);
			await repository.updateEventAsn(event.id, asn ?? NO_ASN, org ?? "Unknown");
		}
		for (const session of sessions) {
			const { asn, org } = asnForStorage(session.initial_ip);
			await repository.updateSessionAsn(session.id, asn ?? NO_ASN, org ?? "Unknown");
		}
	}
}
