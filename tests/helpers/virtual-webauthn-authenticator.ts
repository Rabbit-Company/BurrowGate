import { encodeCBOR } from "@levischuck/tiny-cbor";
import { toBase64Url } from "../../src/utils/crypto.ts";

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
	const total = arrays.reduce((sum, array) => sum + array.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const array of arrays) {
		out.set(array, offset);
		offset += array.length;
	}
	return out;
}

async function rpIdHash(rpID: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpID)));
}

function flagsByte(userPresent: boolean, attestedCredentialData: boolean): Uint8Array {
	let flags = 0;
	if (userPresent) flags |= 0x01;
	if (attestedCredentialData) flags |= 0x40;
	return new Uint8Array([flags]);
}

function signCountBytes(count: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, count, false);
	return bytes;
}

function trimLeadingZeros(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) index += 1;
	return bytes.slice(index);
}

function toDerInteger(bytes: Uint8Array): Uint8Array {
	let trimmed = trimLeadingZeros(bytes);
	if ((trimmed[0] ?? 0) & 0x80) trimmed = concatBytes(new Uint8Array([0]), trimmed);
	return concatBytes(new Uint8Array([0x02, trimmed.length]), trimmed);
}

/** WebAuthn/COSE signatures are DER-encoded; WebCrypto produces raw IEEE-P1363 (r||s). Convert between the two. */
function derEncodeEcdsaSignature(raw: Uint8Array): Uint8Array {
	const r = toDerInteger(raw.slice(0, 32));
	const s = toDerInteger(raw.slice(32, 64));
	const body = concatBytes(r, s);
	return concatBytes(new Uint8Array([0x30, body.length]), body);
}

export interface VirtualAuthenticator {
	credentialId: string;
	createRegistrationResponse(challenge: string, rpID: string, origin: string): Promise<any>;
	createAuthenticationResponse(challenge: string, rpID: string, origin: string, signCount: number): Promise<any>;
}

export async function createVirtualAuthenticator(): Promise<VirtualAuthenticator> {
	const credentialIdBytes = crypto.getRandomValues(new Uint8Array(32));
	const credentialId = toBase64Url(credentialIdBytes);
	const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
	const x = rawPublicKey.slice(1, 33);
	const y = rawPublicKey.slice(33, 65);
	const coseKey = new Map<number, unknown>([
		[1, 2], // kty: EC2
		[3, -7], // alg: ES256
		[-1, 1], // crv: P-256
		[-2, x],
		[-3, y],
	]);
	const publicKeyCbor = encodeCBOR(coseKey as any);

	async function sign(data: Uint8Array): Promise<Uint8Array> {
		const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, data as any));
		return derEncodeEcdsaSignature(raw);
	}

	return {
		credentialId,
		async createRegistrationResponse(challenge, rpID, origin) {
			const aaguid = new Uint8Array(16);
			const credIdLen = new Uint8Array(2);
			new DataView(credIdLen.buffer).setUint16(0, credentialIdBytes.length, false);
			const attestedCredentialData = concatBytes(aaguid, credIdLen, credentialIdBytes, publicKeyCbor);
			const authData = concatBytes(await rpIdHash(rpID), flagsByte(true, true), signCountBytes(0), attestedCredentialData);
			const attestationObject = encodeCBOR(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]) as any);
			const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				clientExtensionResults: {},
				response: {
					clientDataJSON: toBase64Url(clientDataJSON),
					attestationObject: toBase64Url(attestationObject),
					transports: ["usb"],
				},
			};
		},
		async createAuthenticationResponse(challenge, rpID, origin, signCount) {
			const authData = concatBytes(await rpIdHash(rpID), flagsByte(true, false), signCountBytes(signCount));
			const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
			const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
			const signature = await sign(concatBytes(authData, clientDataHash));
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				clientExtensionResults: {},
				response: {
					clientDataJSON: toBase64Url(clientDataJSON),
					authenticatorData: toBase64Url(authData),
					signature: toBase64Url(signature),
				},
			};
		},
	};
}
