const output = document.querySelector("#output");
const identity = document.querySelector("#identity");
const status = document.querySelector("#status");
const mintButton = document.querySelector("#mint");
const callButton = document.querySelector("#call-api");
const repeatedButton = document.querySelector("#call-repeatedly");
const logoutButton = document.querySelector("#logout");
const revokedButton = document.querySelector("#call-revoked");

let assertion = null;
let previousAssertion = null;
let demoConfig = null;

function showStatus(message, kind = "") {
	status.textContent = message;
	status.dataset.kind = kind;
}

function showOutput(value) {
	output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function jsonRequest(url, options) {
	const response = await fetch(url, options);
	let body;
	try {
		body = await response.json();
	} catch {
		body = { error: `Non-JSON response with status ${response.status}` };
	}
	if (!response.ok) throw Object.assign(new Error(body.error ?? `Request failed with ${response.status}`), { response, body });
	return body;
}

async function mintAssertion() {
	assertion = await jsonRequest("/_burrowgate/access/session-token", {
		method: "POST",
		credentials: "same-origin",
		headers: { accept: "application/json" },
	});
	identity.textContent = `${assertion.user.username} (${assertion.user.id})`;
	showStatus(`Assertion ready until ${new Date(assertion.expiresAt).toLocaleTimeString()}.`, "ok");
	showOutput({ ...assertion, token: `${assertion.token.slice(0, 32)}...` });
}

async function callApi(path = "/api/me") {
	if (!assertion) await mintAssertion();
	const result = await jsonRequest(`${demoConfig.backendOrigin}${path}`, {
		headers: { "X-BurrowGate-Session-Assertion": assertion.token },
	});
	showStatus("Backend accepted the assertion.", "ok");
	showOutput(result);
	return result;
}

mintButton.addEventListener("click", async () => {
	try {
		await mintAssertion();
	} catch (error) {
		showStatus(error.message, "error");
		showOutput(error.body ?? String(error));
	}
});

callButton.addEventListener("click", async () => {
	try {
		await callApi();
	} catch (error) {
		showStatus(error.message, "error");
		showOutput(error.body ?? String(error));
	}
});

repeatedButton.addEventListener("click", async () => {
	try {
		const results = [];
		for (let index = 0; index < 3; index += 1) results.push(await callApi("/api/private-data"));
		showStatus("Three calls completed. The introspection counter should increase at most once within the cache TTL.", "ok");
		showOutput(results.map((result) => result.diagnostics));
	} catch (error) {
		showStatus(error.message, "error");
		showOutput(error.body ?? String(error));
	}
});

logoutButton.addEventListener("click", async () => {
	try {
		previousAssertion = assertion;
		const result = await jsonRequest("/_burrowgate/access/logout", { method: "POST", credentials: "same-origin" });
		assertion = null;
		identity.textContent = "Logged out";
		showStatus(
			`BurrowGate session revoked. A previously cached backend result may remain valid for up to ${demoConfig.cacheTtlMs} ms. Reload to sign in again.`,
			"ok",
		);
		showOutput({ result, previousAssertionPrefix: previousAssertion?.token.slice(0, 32) });
	} catch (error) {
		showStatus(error.message, "error");
		showOutput(error.body ?? String(error));
	}
});

revokedButton.addEventListener("click", async () => {
	if (!previousAssertion) {
		showStatus("Log out after minting an assertion first.", "error");
		return;
	}
	try {
		const result = await jsonRequest(`${demoConfig.backendOrigin}/api/me`, {
			headers: { "X-BurrowGate-Session-Assertion": previousAssertion.token },
		});
		showStatus(`The backend still had the successful result cached. Retry after ${demoConfig.cacheTtlMs} ms.`, "error");
		showOutput(result);
	} catch (error) {
		showStatus(
			error.response?.status === 401 ? "The previous assertion is now rejected, as expected." : error.message,
			error.response?.status === 401 ? "ok" : "error",
		);
		showOutput(error.body ?? String(error));
	}
});

try {
	demoConfig = await jsonRequest("/demo-config");
	if (location.protocol === "https:" && demoConfig.backendOrigin.startsWith("http:")) {
		throw new Error(
			`Mixed-content configuration: this page uses HTTPS but DEMO_BACKEND_PUBLIC_ORIGIN is ${demoConfig.backendOrigin}. Use the API site's HTTPS BurrowGate URL, not its local origin.`,
		);
	}
	if (!demoConfig.allowedFrontendOrigins.includes(location.origin)) {
		throw new Error(`CORS configuration does not allow ${location.origin}. Add it to DEMO_ALLOWED_FRONTEND_ORIGINS and restart the example.`);
	}
	showStatus(`Frontend ${location.origin} will call ${demoConfig.backendOrigin}. Mint an assertion to begin.`);
} catch (error) {
	showStatus(error.message, "error");
	showOutput(error.body ?? String(error));
}
