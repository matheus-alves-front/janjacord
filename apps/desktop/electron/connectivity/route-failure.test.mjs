import { describe, expect, it } from "vitest";
import { classifyRouteFailure, describeRouteProbe, formatRouteDiagnostic } from "./route-failure.mjs";

describe("route failure classification", () => {
  it("names the layer that failed instead of blaming the clock", () => {
    const tls = classifyRouteFailure(
      { code: "DEPTH_ZERO_SELF_SIGNED_CERT", message: "self signed certificate" },
      { error: "self signed certificate" },
    );
    expect(tls).toBe("route_tls_blocked");

    // O HostClient só vê o fechamento; o probe é quem revela o DNS quebrado.
    const dns = classifyRouteFailure(
      { code: "closed_before_open", message: "connection closed before the handshake completed" },
      { error: "getaddrinfo ENOTFOUND abc.shares.zrok.io" },
    );
    expect(dns).toBe("route_dns");

    expect(classifyRouteFailure({ code: "ECONNREFUSED", message: "connect ECONNREFUSED 127.0.0.1:443" }, null))
      .toBe("route_refused");
    expect(classifyRouteFailure({ code: "timeout", message: "host não abriu a sessão em 15000 ms" }, { error: "tcp_timeout" }))
      .toBe("route_unreachable");
  });

  it("reads the edge status when the transport stayed silent", () => {
    const silent = { code: "closed_before_open", message: "connection closed before the handshake completed" };
    expect(classifyRouteFailure(silent, { status: 404 })).toBe("route_missing");
    expect(classifyRouteFailure(silent, { status: 502 })).toBe("route_backend_down");
  });

  it("keeps timeout meaning only 'the budget ran out'", () => {
    expect(classifyRouteFailure({ code: "timeout", message: "host não abriu a sessão em 15000 ms" }, { ok: false, status: null, error: null }))
      .toBe("timeout");
    expect(classifyRouteFailure(null, null)).toBe("timeout");
  });

  it("carries the measured phases and the raw cause in the copyable line", () => {
    const line = formatRouteDiagnostic(
      "wss://abc.shares.zrok.io/signal",
      { code: "DEPTH_ZERO_SELF_SIGNED_CERT", message: "self signed certificate" },
      { phases: { dns: 4, tcp: 21, tls: 60 }, error: "self signed certificate" },
    );
    expect(line).toContain("wss://abc.shares.zrok.io/signal");
    expect(line).toContain("dns 4ms");
    expect(line).toContain("tcp 21ms");
    expect(line).toContain("tls 60ms");
    expect(line).toContain("probe: self signed certificate");
    expect(line).toContain("transporte: DEPTH_ZERO_SELF_SIGNED_CERT self signed certificate");
  });
});

describe("pre-join route probe summary", () => {
  it("reports a healthy route with its timings", () => {
    const summary = describeRouteProbe("wss://ok.shares.zrok.io/signal", {
      ok: true,
      status: 101,
      statusLine: "HTTP/1.1 101 Switching Protocols",
      phases: { dns: 1, tcp: 2, tls: 3, ws: 4 },
      total: 10,
    });
    expect(summary).toMatchObject({ ok: true, status: 101, code: "ok", error: null });
    expect(summary.diagnostic).toContain("ws 4ms");
  });

  it("reports the blocking layer for an unreachable route", () => {
    const summary = describeRouteProbe("wss://dead.shares.zrok.io/signal", {
      ok: false,
      status: null,
      phases: { dns: 3 },
      error: "connect ECONNREFUSED 127.0.0.1:443",
    });
    expect(summary).toMatchObject({ ok: false, code: "route_refused" });
    expect(summary.diagnostic).toContain("dns 3ms");
    expect(summary.diagnostic).toContain("ECONNREFUSED");
  });
});
