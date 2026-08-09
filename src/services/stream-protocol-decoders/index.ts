import { registerStreamProtocolDecoder } from "./registry.ts";
import { minecraftJavaDecoder } from "./minecraft-java.ts";

registerStreamProtocolDecoder(minecraftJavaDecoder);

export { registerStreamProtocolDecoder, streamProtocolDecoder } from "./registry.ts";
export type { StreamDecodeAttempt, StreamProtocolDecoder } from "./registry.ts";
