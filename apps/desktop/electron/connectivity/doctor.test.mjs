import { describe, expect, it } from "vitest";
import { parseAgentShares, probeEdgeDetailed, runConnectivityDoctor } from "./doctor.mjs";

const AGENT_STATUS = [
  "SHARES",
  "╭──────────────┬────────────┬──────────────┬────────────────────────────┬───────────────────────┬────────╮",
  "│ SHARE TOKEN  │ SHARE MODE │ BACKEND MODE │ FRONTEND ENDPOINTS         │ TARGET                │ STATUS │",
  "├──────────────┼────────────┼──────────────┼────────────────────────────┼───────────────────────┼────────╤",
  "│ err_p9MT1wSb │ public     │ proxy        │                            │ http://127.0.0.1:8931 │ \x1b[33mretrying\x1b[0m │",
  "│ 26nnwy5hnv34 │ public     │ proxy        │ felllassss.shares.zrok.io │ http://127.0.0.1:8931 │ \x1b[32mactive\x1b[0m   │",
  "╰──────────────┴────────────┴──────────────┴────────────────────────────┴───────────────────────┴────────╯",
  "1 active, 1 retrying, 0 failed",
].join("\n");

describe("doctor agent parsing", () => {
  it("parses share rows stripping ANSI and skipping header/empty endpoints", () => {
    const shares = parseAgentShares(AGENT_STATUS);
    expect(shares).toHaveLength(2);
    expect(shares[0]).toMatchObject({ token: "err_p9MT1wSb", endpoint: null, status: "retrying" });
    expect(shares[1]).toMatchObject({ token: "26nnwy5hnv34", endpoint: "felllassss.shares.zrok.io", status: "active" });
  });

  it("returns empty for garbage input", () => {
    expect(parseAgentShares("")).toEqual([]);
    expect(parseAgentShares(undefined)).toEqual([]);
  });
});

describe("connectivity doctor", () => {
  it("reports all green when backend, agent and edge are healthy", async () => {
    const net = await import("node:net");
    const server = net.createServer(() => {});
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const report = await runConnectivityDoctor({
        activeRoute: { provider: "zrok", endpoint: "wss://felllassss.shares.zrok.io/signal" },
        backendPort: port,
        runAgentStatus: async () => AGENT_STATUS,
        probe: async () => ({ ok: true, status: 101, total: 1234, phases: { dns: 1, tcp: 2, tls: 3, ws: 4 } }),
      });
      expect(report.overall).toBe("ok");
      expect(report.checks.map((check) => check.ok)).toEqual([true, true, true, true]);
      expect(report.hints).toEqual([]);
    } finally {
      server.close();
    }
  });

  it("adds actionable hints when the agent lost the share and the edge 404s", async () => {
    const report = await runConnectivityDoctor({
      activeRoute: { provider: "zrok", endpoint: "wss://fellasssss.shares.zrok.io/signal" },
      backendPort: 1, // porta fechada: host falha rápido
      runAgentStatus: async () => AGENT_STATUS,
      probe: async () => ({ ok: false, status: 404, total: 300, phases: {} }),
    });
    expect(report.overall).toBe("degraded");
    const ids = report.checks.filter((check) => !check.ok).map((check) => check.id);
    expect(ids).toContain("host");
    expect(ids).toContain("agent");
    expect(ids).toContain("edge");
    expect(report.hints.join("\n")).toMatch(/órfã/i);
  });

  it("reports route missing when nothing is active", async () => {
    const report = await runConnectivityDoctor({ activeRoute: null, backendPort: 1 });
    expect(report.overall).toBe("down");
    expect(report.checks.find((check) => check.id === "route")?.ok).toBe(false);
    expect(report.hints.join("\n")).toMatch(/nenhuma rota externa/i);
  });

  it("skips the agent check for non-zrok providers", async () => {
    const report = await runConnectivityDoctor({
      activeRoute: { provider: "manual", endpoint: "wss://chat.example.com/signal" },
      backendPort: 1,
      probe: async () => ({ ok: true, status: 101, total: 50, phases: {} }),
    });
    expect(report.checks.find((check) => check.id === "agent")).toBeUndefined();
    expect(report.overall).toBe("degraded"); // host caiu, mas rota ok
  });
});

describe("edge probe failure shape", () => {
  it("resolves with ok:false and an error field for unreachable hosts", async () => {
    const result = await probeEdgeDetailed("wss://nao-existe-janjacord.invalid/signal", { timeoutMs: 2_000 });
    expect(result.ok).toBe(false);
    expect(result.status).toBeNull();
    expect(typeof result.total).toBe("number");
  });
});
