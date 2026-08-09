import type { StreamDecodeAttempt, StreamProtocolDecoder } from "./registry.ts";

/**
 * Decodes the initial, always-unencrypted part of a Minecraft Java Edition connection: the
 * Handshake packet, and (when the handshake requests the login state) the Login Start packet
 * that immediately follows it. This is intentionally narrow. It reads just enough to populate the
 * "handshake"/"login" fields the minecraft-java ruleset uses (see
 * rulesets/minecraft-java.stream-ruleset.json) and nothing else. It cannot and does not attempt to
 * parse anything past that point - once an online-mode server enables encryption, every later byte
 * is opaque ciphertext to a proxy that isn't part of that handshake.
 *
 * Wire format reference: https://minecraft.wiki/w/Java_Edition_protocol
 * Packets are [VarInt length][VarInt packetId][...fields], length counts everything after itself.
 */

const HANDSHAKE_PACKET_ID = 0x00;
const LOGIN_START_PACKET_ID = 0x00;
const LOGIN_NEXT_STATE = 2;
const MAX_PACKET_LENGTH = 65_535;
const MAX_SERVER_ADDRESS_BYTES = 300; // generous: spec caps at 255 chars, but BungeeCord/Velocity IP-forwarding appends extra data
const MAX_USERNAME_BYTES = 64; // spec caps usernames at 16 characters; leaves headroom for multi-byte encoding of garbage input

interface VarIntResult {
	value: number;
	bytesRead: number;
}

/** Returns null when more bytes are needed, or "invalid" when the VarInt itself is malformed (too long). */
function readVarInt(buffer: Uint8Array, offset: number): VarIntResult | null | "invalid" {
	let value = 0;
	let position = 0;
	let cursor = offset;
	for (let iterations = 0; iterations < 5; iterations += 1) {
		if (cursor >= buffer.length) return null;
		const byte = buffer[cursor]!;
		cursor += 1;
		value |= (byte & 0x7f) << position;
		if ((byte & 0x80) === 0) return { value: value | 0, bytesRead: cursor - offset };
		position += 7;
	}
	return "invalid";
}

interface StringResult {
	value: string;
	bytesRead: number;
}

function readString(buffer: Uint8Array, offset: number, maxBytes: number): StringResult | null | "invalid" {
	const length = readVarInt(buffer, offset);
	if (length === null) return null;
	if (length === "invalid") return "invalid";
	if (length.value < 0 || length.value > maxBytes) return "invalid";
	const start = offset + length.bytesRead;
	const end = start + length.value;
	if (end > buffer.length) return null;
	try {
		return { value: new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(start, end)), bytesRead: length.bytesRead + length.value };
	} catch {
		return "invalid";
	}
}

interface PacketFrame {
	payloadStart: number;
	payloadEnd: number;
}

/** Reads the [VarInt length] prefix and returns the bounds of the payload that follows, once fully buffered. */
function readPacketFrame(buffer: Uint8Array, offset: number): PacketFrame | null | "invalid" {
	const length = readVarInt(buffer, offset);
	if (length === null) return null;
	if (length === "invalid") return "invalid";
	if (length.value < 0 || length.value > MAX_PACKET_LENGTH) return "invalid";
	const payloadStart = offset + length.bytesRead;
	const payloadEnd = payloadStart + length.value;
	if (payloadEnd > buffer.length) return null;
	return { payloadStart, payloadEnd };
}

interface HandshakeFields {
	protocolVersion: number;
	serverAddress: string;
	serverAddressLength: number;
	nextState: number;
}

/** view is exactly one packet's payload; any read that would run past its end is definitively malformed, not "need more bytes". */
function decodeHandshakePayload(view: Uint8Array): HandshakeFields | "invalid" {
	const id = readVarInt(view, 0);
	if (id === null || id === "invalid" || id.value !== HANDSHAKE_PACKET_ID) return "invalid";
	let offset = id.bytesRead;

	const protocolVersion = readVarInt(view, offset);
	if (protocolVersion === null || protocolVersion === "invalid") return "invalid";
	offset += protocolVersion.bytesRead;

	const serverAddress = readString(view, offset, MAX_SERVER_ADDRESS_BYTES);
	if (serverAddress === null || serverAddress === "invalid") return "invalid";
	offset += serverAddress.bytesRead;

	if (offset + 2 > view.length) return "invalid";
	offset += 2; // server port (unsigned short) - not exposed as a rule field, only skipped

	const nextState = readVarInt(view, offset);
	if (nextState === null || nextState === "invalid") return "invalid";

	return {
		protocolVersion: protocolVersion.value,
		serverAddress: serverAddress.value,
		serverAddressLength: serverAddress.value.length,
		nextState: nextState.value,
	};
}

interface LoginStartFields {
	username: string;
	usernameLength: number;
}

function decodeLoginStartPayload(view: Uint8Array): LoginStartFields | "invalid" {
	const id = readVarInt(view, 0);
	if (id === null || id === "invalid" || id.value !== LOGIN_START_PACKET_ID) return "invalid";
	const username = readString(view, id.bytesRead, MAX_USERNAME_BYTES);
	if (username === null || username === "invalid") return "invalid";
	return { username: username.value, usernameLength: username.value.length };
}

function decode(buffer: Uint8Array): StreamDecodeAttempt {
	const handshakeFrame = readPacketFrame(buffer, 0);
	if (handshakeFrame === null) return { status: "incomplete", fields: {} };
	if (handshakeFrame === "invalid") return { status: "done", fields: { handshake_valid: false } };

	const handshake = decodeHandshakePayload(buffer.subarray(handshakeFrame.payloadStart, handshakeFrame.payloadEnd));
	if (handshake === "invalid") return { status: "done", fields: { handshake_valid: false } };

	const baseFields = {
		handshake_valid: true,
		protocol_version: handshake.protocolVersion,
		server_address: handshake.serverAddress,
		server_address_length: handshake.serverAddressLength,
		next_state: handshake.nextState,
	};

	if (handshake.nextState !== LOGIN_NEXT_STATE) return { status: "done", fields: baseFields };

	const loginFrame = readPacketFrame(buffer, handshakeFrame.payloadEnd);
	if (loginFrame === null) return { status: "incomplete", fields: baseFields };
	if (loginFrame === "invalid") return { status: "done", fields: baseFields };

	const login = decodeLoginStartPayload(buffer.subarray(loginFrame.payloadStart, loginFrame.payloadEnd));
	if (login === "invalid") return { status: "done", fields: baseFields };

	return { status: "done", fields: { ...baseFields, username: login.username, username_length: login.usernameLength } };
}

export const minecraftJavaDecoder: StreamProtocolDecoder = { protocol: "minecraft-java", decode };
