interface DemoSocketData {
	connectedAt: number;
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);
}

function headersTable(headers: Headers): string {
	const rows = [...headers.entries()].sort(([left], [right]) => left.localeCompare(right));
	return `<table>
      <thead><tr><th>Header</th><th>Value</th></tr></thead>
      <tbody>
        ${rows
					.map(
						([name, value]) =>
							`<tr class="${name.startsWith("x-burrowgate-") ? "burrowgate" : ""}"><td>${escapeHtml(name)}</td><td>${escapeHtml(value)}</td></tr>`,
					)
					.join("\n        ")}
      </tbody>
    </table>`;
}

const server = Bun.serve<DemoSocketData>({
	port: 3000,
	fetch(request, server) {
		const url = new URL(request.url);

		if (url.pathname === "/ws") {
			const upgraded = server.upgrade(request, {
				data: { connectedAt: Date.now() },
			});
			if (upgraded) return;
			return new Response("WebSocket upgrade required", {
				status: 426,
				headers: { upgrade: "websocket" },
			});
		}

		return new Response(
			`<!doctype html>
<html>
  <head>
    <style>
      table { border-collapse: collapse; margin: 1rem 0; }
      th, td { border: 1px solid #ccc; padding: 0.35rem 0.75rem; text-align: left; font-size: 0.9rem; }
      th { background: #f2f2f2; }
      tr.burrowgate td { background: #eef6ff; }
    </style>
  </head>
  <body style="font-family:system-ui;padding:3rem">
    <h1>Protected origin reached</h1>
    <p>Path: <code>${url.pathname}</code></p>
    <h2>Request headers</h2>
    ${headersTable(request.headers)}
    <button id="connect">Connect WebSocket</button>
    <pre id="output">Not connected</pre>
    <script>
      document.getElementById("connect").addEventListener("click", () => {
        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const socket = new WebSocket(protocol + "//" + location.host + "/ws");
        const output = document.getElementById("output");
        socket.addEventListener("open", () => {
          output.textContent = "Connected; sending echo test...";
          socket.send("Hello through BurrowGate");
        });
        socket.addEventListener("message", (event) => {
          output.textContent += "\\nReceived: " + event.data;
        });
        socket.addEventListener("close", (event) => {
          output.textContent += "\\nClosed: " + event.code + " " + event.reason;
        });
        socket.addEventListener("error", () => {
          output.textContent += "\\nWebSocket error";
        });
      });
    </script>
  </body>
</html>`,
			{ headers: { "content-type": "text/html; charset=utf-8" } },
		);
	},
	websocket: {
		open(socket) {
			socket.send(`Connected to demo origin at ${new Date(socket.data.connectedAt).toISOString()}`);
		},
		message(socket, message) {
			socket.send(typeof message === "string" ? `Echo: ${message}` : message);
		},
	},
});

console.log(`Demo origin listening on ${server.url}`);
console.log(`WebSocket echo endpoint: ws://localhost:${server.port}/ws`);
