import { describe, expect, it } from "vitest";
import {
  CLOUDFLARE_TURN_MINT_ENDPOINT,
  filterCloudflareTurnIceServers,
  mintCloudflareTurnIceServers,
  validateCloudflareTurnConfig,
} from "./cloudflare-turn.mjs";

function fakeFetch(status, body, headers = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return {
      status,
      ok: status >= 200 && status < 300,
      json: async () => body,
      headers,
    };
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

describe("cloudflare turn mint", () => {
  it("mints iceServers from a 201 response and strips the port-53 URLs", async () => {
    const fetchImpl = fakeFetch(201, {
      iceServers: [
        { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"] },
        {
          urls: [
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turn:turn.cloudflare.com:53?transport=udp",
            "turns:turn.cloudflare.com:443?transport=tcp",
          ],
          username: "user-abc",
          credential: "cred-abc",
        },
      ],
    });

    const result = await mintCloudflareTurnIceServers({
      keyId: "turn-key-123",
      apiToken: "api-token-1234567890abcdef",
      ttl: 3600,
      fetchImpl,
      now: 1_000,
    });

    expect(result.mintedAt).toBe(1_000);
    expect(result.ttl).toBe(3600);
    const allUrls = result.iceServers.flatMap((entry) => entry.urls);
    expect(allUrls).not.toContain("stun:stun.cloudflare.com:53");
    expect(allUrls).not.toContain("turn:turn.cloudflare.com:53?transport=udp");
    expect(allUrls).toContain("turn:turn.cloudflare.com:3478?transport=udp");
    expect(result.iceServers[1]).toMatchObject({ username: "user-abc", credential: "cred-abc" });
    expect(fetchImpl.calls).toHaveLength(1);
    expect(fetchImpl.calls[0].url).toBe(`${CLOUDFLARE_TURN_MINT_ENDPOINT}/turn-key-123/credentials/generate-ice-servers`);
    expect(fetchImpl.calls[0].options.method).toBe("POST");
    expect(fetchImpl.calls[0].options.headers.Authorization).toBe("Bearer api-token-1234567890abcdef");
    expect(JSON.parse(fetchImpl.calls[0].options.body)).toEqual({ ttl: 3600 });
  });

  it("clamps ttl to the documented maximum", async () => {
    const fetchImpl = fakeFetch(201, { iceServers: [{ urls: ["turn:turn.cloudflare.com:443?transport=tcp"] }] });
    await mintCloudflareTurnIceServers({ keyId: "key-123456", apiToken: "t".repeat(32), ttl: 999_999, fetchImpl });
    expect(JSON.parse(fetchImpl.calls[0].options.body)).toEqual({ ttl: 86_400 });
  });

  it("maps 401/403 to an actionable auth error without leaking the token", async () => {
    await expect(mintCloudflareTurnIceServers({
      keyId: "key-123456",
      apiToken: "secret-token-1234567890",
      fetchImpl: fakeFetch(403, {}),
    })).rejects.toMatchObject({ code: "turn_auth_failed" });
  });

  it("rejects invalid config before any network call", async () => {
    const fetchImpl = fakeFetch(201, { iceServers: [] });
    await expect(mintCloudflareTurnIceServers({ keyId: "x y", apiToken: "token", fetchImpl }))
      .rejects.toMatchObject({ code: "invalid_config" });
    await expect(mintCloudflareTurnIceServers({ keyId: "k", apiToken: "short", fetchImpl }))
      .rejects.toMatchObject({ code: "invalid_config" });
    expect(fetchImpl.calls).toHaveLength(0);
  });

  it("rejects a response without usable iceServers", async () => {
    await expect(mintCloudflareTurnIceServers({
      keyId: "key-123456",
      apiToken: "t".repeat(32),
      fetchImpl: fakeFetch(201, { iceServers: [] }),
    })).rejects.toMatchObject({ code: "turn_mint_failed" });
  });

  it("filters malformed entries and keeps credentials only when present", () => {
    const filtered = filterCloudflareTurnIceServers([
      null,
      { urls: ["stun:stun.cloudflare.com:53"] },
      { urls: ["turn:turn.cloudflare.com:443?transport=tcp"], username: "u", credential: "c" },
    ]);
    expect(filtered).toHaveLength(1);
    expect(filtered[0]).toEqual({
      urls: ["turn:turn.cloudflare.com:443?transport=tcp"],
      username: "u",
      credential: "c",
    });
  });

  it("validates key id and api token shapes", () => {
    expect(() => validateCloudflareTurnConfig("key-123456", "token-1234567890abc")).not.toThrow();
    expect(() => validateCloudflareTurnConfig("", "token")).toThrowError(/TURN Key ID/);
    expect(() => validateCloudflareTurnConfig("key-123456", "a".repeat(15))).toThrowError(/API token/);
  });
});
