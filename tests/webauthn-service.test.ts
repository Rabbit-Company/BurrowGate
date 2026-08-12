import { describe, expect, test } from "bun:test";
import { buildAuthenticationOptions, buildRegistrationOptions, verifyAuthentication, verifyRegistration } from "../src/services/webauthn-service.ts";
import { createVirtualAuthenticator } from "./helpers/virtual-webauthn-authenticator.ts";

const RP_ID = "example.test";
const ORIGIN = "https://example.test";

async function registerCredential() {
	const authenticator = await createVirtualAuthenticator();
	const options = await buildRegistrationOptions({ rpID: RP_ID, userId: "user_1", username: "alice", excludeCredentials: [] });
	const response = await authenticator.createRegistrationResponse(options.challenge, RP_ID, ORIGIN);
	const verified = await verifyRegistration({ response, expectedChallenge: options.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID });
	return { authenticator, verified };
}

describe("webauthn-service registration", () => {
	test("verifies a genuine registration response and returns storable credential fields", async () => {
		const { verified, authenticator } = await registerCredential();
		expect(verified.credentialId).toBe(authenticator.credentialId);
		expect(verified.signCount).toBe(0);
		expect(verified.publicKey.length).toBeGreaterThan(0);
		expect(verified.credentialIdHash).toMatch(/^[0-9a-f]{64}$/u);
	});

	test("rejects a registration response signed for the wrong rpID", async () => {
		const authenticator = await createVirtualAuthenticator();
		const options = await buildRegistrationOptions({ rpID: RP_ID, userId: "user_1", username: "alice", excludeCredentials: [] });
		const response = await authenticator.createRegistrationResponse(options.challenge, "attacker.test", ORIGIN);
		await expect(verifyRegistration({ response, expectedChallenge: options.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID })).rejects.toThrow();
	});

	test("rejects a registration response for a different challenge", async () => {
		const authenticator = await createVirtualAuthenticator();
		const options = await buildRegistrationOptions({ rpID: RP_ID, userId: "user_1", username: "alice", excludeCredentials: [] });
		const response = await authenticator.createRegistrationResponse("wrong-challenge", RP_ID, ORIGIN);
		await expect(verifyRegistration({ response, expectedChallenge: options.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID })).rejects.toThrow();
	});
});

describe("webauthn-service authentication", () => {
	test("verifies a genuine authentication response signed by the registered key", async () => {
		const { authenticator, verified } = await registerCredential();
		const options = await buildAuthenticationOptions({
			rpID: RP_ID,
			allowCredentials: [{ credentialId: verified.credentialId, transports: verified.transports }],
		});
		const response = await authenticator.createAuthenticationResponse(options.challenge, RP_ID, ORIGIN, 1);
		const result = await verifyAuthentication({
			response,
			expectedChallenge: options.challenge,
			expectedOrigin: ORIGIN,
			expectedRPID: RP_ID,
			credential: { credentialId: verified.credentialId, publicKey: verified.publicKey, signCount: verified.signCount, transports: verified.transports },
		});
		expect(result.newCounter).toBe(1);
	});

	test("rejects an authentication response whose signature does not match the stored public key", async () => {
		const { verified } = await registerCredential();
		const impostor = await createVirtualAuthenticator();
		const options = await buildAuthenticationOptions({
			rpID: RP_ID,
			allowCredentials: [{ credentialId: verified.credentialId, transports: verified.transports }],
		});
		const response = await impostor.createAuthenticationResponse(options.challenge, RP_ID, ORIGIN, 1);
		await expect(
			verifyAuthentication({
				response,
				expectedChallenge: options.challenge,
				expectedOrigin: ORIGIN,
				expectedRPID: RP_ID,
				credential: { credentialId: verified.credentialId, publicKey: verified.publicKey, signCount: verified.signCount, transports: verified.transports },
			}),
		).rejects.toThrow();
	});

	test("rejects a non-advancing signature counter (clone detection)", async () => {
		const { authenticator, verified } = await registerCredential();
		const options = await buildAuthenticationOptions({
			rpID: RP_ID,
			allowCredentials: [{ credentialId: verified.credentialId, transports: verified.transports }],
		});
		// Stored sign count is already ahead of what this "clone" reports (0 <= storedSignCount of 5).
		const response = await authenticator.createAuthenticationResponse(options.challenge, RP_ID, ORIGIN, 0);
		await expect(
			verifyAuthentication({
				response,
				expectedChallenge: options.challenge,
				expectedOrigin: ORIGIN,
				expectedRPID: RP_ID,
				credential: { credentialId: verified.credentialId, publicKey: verified.publicKey, signCount: 5, transports: verified.transports },
			}),
		).rejects.toThrow();
	});
});
