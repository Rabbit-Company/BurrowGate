import { describe, expect, test } from "bun:test";
import { SITE_EVENT_TYPES, STREAM_EVENT_TYPES } from "../src/ui/notifications-page.ts";
import { NOTIFICATION_EVENT_TYPES, type NotificationEventType } from "../src/types.ts";

/**
 * A notification type missing from the dashboard's catalog is not inert. `isNotificationEventTypeEnabled`
 * treats an absent key as enabled, so the alert is delivered to every webhook subscriber while no
 * control exists to turn it off. These tests pin the catalog to the type list so that cannot happen
 * silently again.
 */

const siteValues = new Set(SITE_EVENT_TYPES.map((option) => option.value));
const streamValues = new Set(STREAM_EVENT_TYPES.map((option) => option.value));
const offered = new Set([...siteValues, ...streamValues]);

/** Types raised only for a stream target, so a site's subscription list has no use for them. */
const STREAM_ONLY: ReadonlySet<string> = new Set<NotificationEventType>(["stream_origin_unhealthy", "stream_origin_recovered", "stream_ip_banned"]);

/** Types raised only against a site. */
const SITE_ONLY: ReadonlySet<string> = new Set<NotificationEventType>([
	"origin_unhealthy",
	"origin_recovered",
	"pool_unhealthy",
	"pool_recovered",
	"ip_banned",
]);

describe("notification event type catalog", () => {
	test("every event type is offered somewhere in the dashboard", () => {
		const missing = NOTIFICATION_EVENT_TYPES.filter((type) => !offered.has(type));
		expect(missing).toEqual([]);
	});

	test("a type that is not stream-only is offered to sites", () => {
		const missing = NOTIFICATION_EVENT_TYPES.filter((type) => !STREAM_ONLY.has(type) && !siteValues.has(type));
		expect(missing).toEqual([]);
	});

	test("a type that is not site-only is offered to streams", () => {
		const missing = NOTIFICATION_EVENT_TYPES.filter((type) => !SITE_ONLY.has(type) && !streamValues.has(type));
		expect(missing).toEqual([]);
	});

	test("the catalogs offer nothing that is not a real event type", () => {
		const known = new Set<string>(NOTIFICATION_EVENT_TYPES);
		expect([...offered].filter((value) => !known.has(value))).toEqual([]);
	});

	test("every offered type carries a label and a description", () => {
		for (const option of [...SITE_EVENT_TYPES, ...STREAM_EVENT_TYPES]) {
			expect(option.label.length).toBeGreaterThan(0);
			expect(option.description.length).toBeGreaterThan(0);
		}
	});

	test("the CrowdSec Local API types are subscribable, not just deliverable", () => {
		expect(siteValues.has("crowdsec_lapi_down")).toBe(true);
		expect(siteValues.has("crowdsec_lapi_up")).toBe(true);
		expect(streamValues.has("crowdsec_lapi_down")).toBe(true);
		expect(streamValues.has("crowdsec_lapi_up")).toBe(true);
	});
});
