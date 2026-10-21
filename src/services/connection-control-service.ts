import { AsyncLocalStorage } from "node:async_hooks";

export interface ConnectionControl {
	release(): boolean;
	abort(): boolean;
}

interface TimeoutCapableServer {
	timeout?(request: Request, seconds: number): void;
}

const connectionControlContext = new AsyncLocalStorage<ConnectionControl>();

export function connectionControlFor(request: Request, server: unknown): ConnectionControl {
	const timeout = (server as TimeoutCapableServer | null)?.timeout;
	const setTimeoutSeconds = (seconds: number): boolean => {
		if (typeof timeout !== "function") return false;
		try {
			timeout.call(server, request, seconds);
			return true;
		} catch {
			return false;
		}
	};
	return { release: () => setTimeoutSeconds(0), abort: () => setTimeoutSeconds(1) };
}

export function withConnectionControl<T>(control: ConnectionControl, callback: () => T): T {
	return connectionControlContext.run(control, callback);
}

export function currentConnectionControl(): ConnectionControl | null {
	return connectionControlContext.getStore() ?? null;
}
