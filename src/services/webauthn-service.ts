import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { WebauthnDeviceType } from "../types.ts";
import { fromBase64Url, sha256Hex, toBase64Url } from "../utils/crypto.ts";

const RP_NAME = "BurrowGate";

export interface WebauthnCredentialRef {
	credentialId: string;
	transports: string[];
}

export interface StoredWebauthnCredential extends WebauthnCredentialRef {
	publicKey: string;
	signCount: number;
}

export interface VerifiedWebauthnRegistration {
	credentialId: string;
	credentialIdHash: string;
	publicKey: string;
	signCount: number;
	transports: string[];
	aaguid: string;
	deviceType: WebauthnDeviceType;
	backedUp: boolean;
}

function asTransports(value: string[]): AuthenticatorTransportFuture[] {
	return value as AuthenticatorTransportFuture[];
}

export async function buildRegistrationOptions(params: {
	rpID: string;
	userId: string;
	username: string;
	excludeCredentials: WebauthnCredentialRef[];
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
	return generateRegistrationOptions({
		rpName: RP_NAME,
		rpID: params.rpID,
		userName: params.username,
		userID: new TextEncoder().encode(params.userId),
		attestationType: "none",
		authenticatorSelection: { residentKey: "discouraged", userVerification: "discouraged" },
		excludeCredentials: params.excludeCredentials.map((credential) => ({
			id: credential.credentialId,
			transports: asTransports(credential.transports),
		})),
	});
}

export async function verifyRegistration(params: {
	response: RegistrationResponseJSON;
	expectedChallenge: string;
	expectedOrigin: string;
	expectedRPID: string;
}): Promise<VerifiedWebauthnRegistration> {
	const result = await verifyRegistrationResponse({
		response: params.response,
		expectedChallenge: params.expectedChallenge,
		expectedOrigin: params.expectedOrigin,
		expectedRPID: params.expectedRPID,
		requireUserVerification: false,
	});
	if (!result.verified || !result.registrationInfo) throw new Error("Security key registration could not be verified");
	const { credential, aaguid, credentialDeviceType, credentialBackedUp } = result.registrationInfo;
	return {
		credentialId: credential.id,
		credentialIdHash: await sha256Hex(credential.id),
		publicKey: toBase64Url(credential.publicKey),
		signCount: credential.counter,
		transports: credential.transports ?? [],
		aaguid,
		deviceType: credentialDeviceType,
		backedUp: credentialBackedUp,
	};
}

export async function buildAuthenticationOptions(params: {
	rpID: string;
	allowCredentials: WebauthnCredentialRef[];
}): Promise<PublicKeyCredentialRequestOptionsJSON> {
	return generateAuthenticationOptions({
		rpID: params.rpID,
		userVerification: "discouraged",
		allowCredentials: params.allowCredentials.map((credential) => ({
			id: credential.credentialId,
			transports: asTransports(credential.transports),
		})),
	});
}

export async function verifyAuthentication(params: {
	response: AuthenticationResponseJSON;
	expectedChallenge: string;
	expectedOrigin: string;
	expectedRPID: string;
	credential: StoredWebauthnCredential;
}): Promise<{ newCounter: number }> {
	const result = await verifyAuthenticationResponse({
		response: params.response,
		expectedChallenge: params.expectedChallenge,
		expectedOrigin: params.expectedOrigin,
		expectedRPID: params.expectedRPID,
		credential: {
			id: params.credential.credentialId,
			publicKey: fromBase64Url(params.credential.publicKey),
			counter: params.credential.signCount,
			transports: asTransports(params.credential.transports),
		},
		requireUserVerification: false,
	});
	if (!result.verified) throw new Error("Security key verification failed");
	return { newCounter: result.authenticationInfo.newCounter };
}
