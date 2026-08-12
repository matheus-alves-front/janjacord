import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("JanjaNode external WebSocket policy", () => {
  it("routes every control client through the shared policy and aborts a stalled push", () => {
    const source = readFileSync(path.join(process.cwd(), "src", "main.ts"), "utf8");
    expect(source).not.toContain("new WebSocket(");
    expect(source).toContain("return createExternalWebSocket(url);");
    expect(source).toContain('ws.terminate();\n            finish(new Error("push handshake timeout"));');
  });
});
