import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { beginPendingLogin, pendingLoginCookie } from "../src/services/admin-auth-service.ts";
import { createAdminUser, resetAdminUserTwoFactor } from "../src/services/admin-user-service.ts";
import { randomId } from "../src/utils/crypto.ts";
import { createVirtualAuthenticator } from "./helpers/virtual-webauthn-authenticator.ts";

const app = new Web();
registerAdminRoutes(app);

const ORIGIN = "https://admin.test";

function pendingCookieHeader(mode: "enroll" | "verify", userId: string): string {
	const token = beginPendingLogin(mode, userId);
	const setCookie = pendingLoginCookie(new Request(ORIGIN), token);
	return setCookie.split(";")[0]!;
}

describe("admin WebAuthn registration and authentication", () => {
	test("a user can register a security key during enrollment and use it to sign in", async () => {
		const user = await createAdminUser({ username: `wak-admin-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
		const authenticator = await createVirtualAuthenticator();

		const enrollCookie = pendingCookieHeader("enroll", user.id);
		const optionsResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/register/options`, { method: "POST", headers: { cookie: enrollCookie } }),
		);
		expect(optionsResponse.status).toBe(200);
		const options = (await optionsResponse.json()) as any;
		expect(options.rp.id).toBe("admin.test");

		const registrationResponse = await authenticator.createRegistrationResponse(options.challenge, "admin.test", ORIGIN);
		const verifyResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/register/verify`, {
				method: "POST",
				headers: { cookie: enrollCookie, "content-type": "application/json" },
				body: JSON.stringify({ response: registrationResponse }),
			}),
		);
		expect(verifyResponse.status).toBe(200);
		const verifyBody = (await verifyResponse.json()) as any;
		expect(Array.isArray(verifyBody.recoveryCodes)).toBe(true);
		expect(verifyBody.recoveryCodes.length).toBeGreaterThan(0);
		expect(verifyResponse.headers.get("set-cookie")).toBeTruthy();

		const stored = await repository.adminWebauthnCredentialsForUser(user.id);
		expect(stored).toHaveLength(1);
		expect(stored[0]!.sign_count).toBe(0);

		// A fresh login now offers WebAuthn verification instead of forcing re-enrollment.
		const verifyCookie = pendingCookieHeader("verify", user.id);
		const authOptionsResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/authenticate/options`, { method: "POST", headers: { cookie: verifyCookie } }),
		);
		expect(authOptionsResponse.status).toBe(200);
		const authOptions = (await authOptionsResponse.json()) as any;

		const authenticationResponse = await authenticator.createAuthenticationResponse(authOptions.challenge, "admin.test", ORIGIN, 7);
		const authVerifyResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/authenticate/verify`, {
				method: "POST",
				headers: { cookie: verifyCookie, "content-type": "application/json" },
				body: JSON.stringify({ response: authenticationResponse }),
			}),
		);
		expect(authVerifyResponse.status).toBe(200);
		expect(authVerifyResponse.headers.get("set-cookie")).toBeTruthy();

		const updated = await repository.adminWebauthnCredentialsForUser(user.id);
		expect(updated[0]!.sign_count).toBe(7);
		expect(updated[0]!.last_used_at).not.toBeNull();
	});

	test("authenticate/verify rejects a response from a key that was never registered", async () => {
		const user = await createAdminUser({ username: `wak-admin-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
		// Register one real credential so the account has a WebAuthn method and "verify" mode is offered.
		await repository.insertAdminWebauthnCredential({
			id: randomId("wak"),
			user_id: user.id,
			rp_id: "admin.test",
			credential_id: randomId("cred"),
			credential_id_hash: randomId("hash"),
			public_key: "cGxhY2Vob2xkZXI",
			sign_count: 0,
			transports_json: JSON.stringify(["usb"]),
			aaguid: "00000000-0000-0000-0000-000000000000",
			device_type: "singleDevice",
			backed_up: 0,
			nickname: null,
			created_at: Date.now(),
			last_used_at: null,
			updated_at: Date.now(),
		});
		const impostor = await createVirtualAuthenticator();

		const verifyCookie = pendingCookieHeader("verify", user.id);
		const authOptionsResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/authenticate/options`, { method: "POST", headers: { cookie: verifyCookie } }),
		);
		const authOptions = (await authOptionsResponse.json()) as any;
		const authenticationResponse = await impostor.createAuthenticationResponse(authOptions.challenge, "admin.test", ORIGIN, 1);

		const authVerifyResponse = await app.handle(
			new Request(`${ORIGIN}/_burrowgate/admin/login/webauthn/authenticate/verify`, {
				method: "POST",
				headers: { cookie: verifyCookie, "content-type": "application/json" },
				body: JSON.stringify({ response: authenticationResponse }),
			}),
		);
		expect(authVerifyResponse.status).toBe(401);
	});
});

describe("resetting an admin's two-factor authentication clears both methods", () => {
	test("resetAdminUserTwoFactor removes the TOTP secret and every registered security key", async () => {
		const user = await createAdminUser({ username: `wak-reset-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
		const existing = await repository.adminUserById(user.id);
		await repository.updateAdminUser({ ...existing!, totp_secret_encrypted: "v1.fake.fake", totp_enrolled_at: Date.now() });
		await repository.insertAdminWebauthnCredential({
			id: randomId("wak"),
			user_id: user.id,
			rp_id: "admin.test",
			credential_id: randomId("cred"),
			credential_id_hash: randomId("hash"),
			public_key: "cGxhY2Vob2xkZXI",
			sign_count: 0,
			transports_json: null,
			aaguid: null,
			device_type: null,
			backed_up: 0,
			nickname: null,
			created_at: Date.now(),
			last_used_at: null,
			updated_at: Date.now(),
		});

		await resetAdminUserTwoFactor(user.id);

		const reloaded = await repository.adminUserById(user.id);
		expect(reloaded!.totp_secret_encrypted).toBeNull();
		expect(await repository.adminWebauthnCredentialsForUser(user.id)).toHaveLength(0);
	});
});
