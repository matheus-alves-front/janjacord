import WebSocket from "ws";
import { randomUUID } from "node:crypto";

const port = Number(process.env.JC_RENDEZVOUS_PORT ?? 8920);
const socket = new WebSocket(`ws://127.0.0.1:${port}/rendezvous`);
const requestId = randomUUID();
const expected = {
  type: "health.ready.result",
  requestId,
  ok: true,
  data: { ready: true, stateLoaded: true },
};
const timer = setTimeout(() => {
  socket.terminate();
  process.exit(1);
}, 3000);

socket.once("open", () => {
  socket.send(JSON.stringify({
    type: "health.ready",
    requestId,
  }));
});

socket.once("message", (raw) => {
  try {
    const actual = JSON.parse(raw.toString());
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("unexpected response");
    clearTimeout(timer);
    socket.close();
    process.exit(0);
  } catch {
    clearTimeout(timer);
    socket.terminate();
    process.exit(1);
  }
});

socket.once("error", () => {
  clearTimeout(timer);
  process.exit(1);
});
