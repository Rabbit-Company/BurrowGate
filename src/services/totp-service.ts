import { generateTOTPSecret, generateTOTPURI, verifyTOTP } from "@rabbit-company/totp";
import QRCode from "qrcode";
import { randomToken, sha256Hex } from "../utils/crypto.ts";

const ISSUER = "BurrowGate";

export function generateSecret(): string {
	return generateTOTPSecret();
}

export function enrollmentUri(username: string, secret: string): string {
	return generateTOTPURI({ accountName: username, issuer: ISSUER, secret });
}

export async function qrSvg(uri: string): Promise<string> {
	return QRCode.toString(uri, { type: "svg" });
}

export async function verifyCode(secret: string, token: string): Promise<boolean> {
	const normalized = String(token ?? "").trim();
	if (!/^\d{6}$/u.test(normalized)) return false;
	return verifyTOTP(normalized, secret, { window: 1 });
}

export interface GeneratedRecoveryCode {
	plaintext: string;
	hash: string;
}

function formatRecoveryCode(raw: string): string {
	const normalized = raw
		.replace(/[^A-Za-z0-9]/gu, "")
		.toUpperCase()
		.slice(0, 16);
	return (normalized.match(/.{1,4}/gu) ?? [normalized]).join("-");
}

export function normalizeRecoveryCode(value: unknown): string {
	return String(value ?? "")
		.replace(/[^A-Za-z0-9]/gu, "")
		.toUpperCase();
}

export async function generateRecoveryCodes(count = 10): Promise<GeneratedRecoveryCode[]> {
	const codes: GeneratedRecoveryCode[] = [];
	for (let index = 0; index < count; index += 1) {
		const plaintext = formatRecoveryCode(randomToken(16));
		codes.push({ plaintext, hash: await sha256Hex(normalizeRecoveryCode(plaintext)) });
	}
	return codes;
}
