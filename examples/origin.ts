interface DemoSocketData {
	connectedAt: number;
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
  <body style="font-family:system-ui;padding:3rem">
    <h1>Protected origin reached</h1>
    <p>Path: <code>${url.pathname}</code></p>
    <p>BurrowGate session: <code>${request.headers.get("x-burrowgate-session-id") ?? "missing"}</code></p>
    <p>Client IP: <code>${request.headers.get("x-burrowgate-client-ip") ?? "missing"}</code></p>
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
