function base64UrlToBuffer(value) {
	const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
	return bytes.buffer;
}

function bufferToBase64Url(buffer) {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function isWebauthnSupported() {
	return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

function toCreationOptions(optionsJSON) {
	return {
		...optionsJSON,
		challenge: base64UrlToBuffer(optionsJSON.challenge),
		user: { ...optionsJSON.user, id: base64UrlToBuffer(optionsJSON.user.id) },
		excludeCredentials: (optionsJSON.excludeCredentials ?? []).map((credential) => ({
			...credential,
			id: base64UrlToBuffer(credential.id),
		})),
	};
}

function toRequestOptions(optionsJSON) {
	return {
		...optionsJSON,
		challenge: base64UrlToBuffer(optionsJSON.challenge),
		allowCredentials: (optionsJSON.allowCredentials ?? []).map((credential) => ({
			...credential,
			id: base64UrlToBuffer(credential.id),
		})),
	};
}

export async function registerCredential(optionsJSON) {
	const credential = await navigator.credentials.create({ publicKey: toCreationOptions(optionsJSON) });
	if (!credential) throw new Error("Security key registration was cancelled");
	const response = credential.response;
	return {
		id: credential.id,
		rawId: credential.id,
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
		clientExtensionResults: credential.getClientExtensionResults(),
		response: {
			clientDataJSON: bufferToBase64Url(response.clientDataJSON),
			attestationObject: bufferToBase64Url(response.attestationObject),
			transports: typeof response.getTransports === "function" ? response.getTransports() : undefined,
		},
	};
}

export async function authenticateWithCredential(optionsJSON) {
	const credential = await navigator.credentials.get({ publicKey: toRequestOptions(optionsJSON) });
	if (!credential) throw new Error("Security key verification was cancelled");
	const response = credential.response;
	return {
		id: credential.id,
		rawId: credential.id,
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
		clientExtensionResults: credential.getClientExtensionResults(),
		response: {
			clientDataJSON: bufferToBase64Url(response.clientDataJSON),
			authenticatorData: bufferToBase64Url(response.authenticatorData),
			signature: bufferToBase64Url(response.signature),
			userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined,
		},
	};
}
