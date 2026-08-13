import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  PROVIDER_IDS,
  createProviderRegistry,
  detectProvider,
  startProvider,
  statusProvider,
  stopProvider,
} from "./index.mjs";

function commandKey(command, args) {
  return `${command} ${args.join(" ")}`;
}

function fakeExecFile(fixtures = {}) {
  const calls = [];
  const execFile = (command, args, options, callback) => {
    calls.push({ command, args, options });
    queueMicrotask(() => {
      const fixture = fixtures[commandKey(command, args)] ?? fixtures[command] ?? { stdout: "ok" };
      if (fixture instanceof Error) {
        callback(fixture, "", "");
        return;
      }
      callback(null, fixture.stdout ?? "", fixture.stderr ?? "");
    });
  };
  execFile.calls = calls;
  return execFile;
}

function fakeSpawn(onSpawn) {
  const calls = [];
  const spawn = (command, args, options) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.exitCode = null;
    child.killed = false;
    child.signals = [];
    child.kill = (signal) => {
      child.signals.push(signal);
      child.killed = true;
      child.exitCode = 0;
      child.emit("exit", 0, signal);
      return true;
    };
    calls.push({ command, args, options, child });
    queueMicrotask(() => onSpawn?.(child, { command, args, options }));
    return child;
  };
  spawn.calls = calls;
  return spawn;
}

describe("connectivity integration API", () => {
  it("exports a stable registry contract for Electron main", () => {
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile: fakeExecFile() });

    expect(PROVIDER_IDS).toEqual({
      TAILSCALE_FUNNEL: "tailscale-funnel",
      NGROK: "ngrok",
      CLOUDFLARED_QUICK: "cloudflared-quick",
      CLOUDFLARED_NAMED: "cloudflared-named",
      MANUAL_NGINX: "manual-nginx",
    });
    expect(Object.keys(registry)).toEqual(["ids", "providers", "get", "detect", "start", "status", "stop"]);
    expect(registry.ids).toEqual(Object.values(PROVIDER_IDS));
    for (const id of registry.ids) {
      expect(Object.keys(registry.providers[id])).toEqual(["id", "detect", "start", "status", "stop"]);
      expect(registry.get(id)).toBe(registry.providers[id]);
    }
    expect(Object.isFrozen(registry)).toBe(true);
    expect(Object.isFrozen(registry.providers)).toBe(true);
    expect([detectProvider, startProvider, statusProvider, stopProvider].every((value) => typeof value === "function")).toBe(true);
    expect(() => registry.get("unsupported")).toThrow(/Unknown connectivity provider/);
  });

  it("detects each CLI with fixed argv and shell disabled", async () => {
    const execFile = fakeExecFile({
      "nginx -v": Object.assign(new Error("missing"), { code: "ENOENT" }),
    });
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile });

    const results = await Promise.all(registry.ids.map((id) => registry.detect(id)));

    expect(execFile.calls.map(({ command, args }) => [command, args])).toEqual([
      ["tailscale", ["version"]],
      ["ngrok", ["version"]],
      ["cloudflared", ["--version"]],
      ["cloudflared", ["--version"]],
      ["nginx", ["-v"]],
    ]);
    expect(execFile.calls.every(({ options }) => options.shell === false)).toBe(true);
    expect(results.slice(0, 4).every((status) => status.state === "available" && status.installed)).toBe(true);
    expect(results[4]).toMatchObject({ provider: "manual-nginx", state: "available", installed: false });
  });

  it("uses the injected spawn for one-shot commands when execFile is omitted", async () => {
    const spawn = fakeSpawn((child) => {
      child.stdout.write("ngrok version 3\n");
      child.exitCode = 0;
      child.emit("exit", 0);
    });
    const registry = createProviderRegistry({ spawn });

    await expect(registry.detect(PROVIDER_IDS.NGROK)).resolves.toMatchObject({ state: "available" });
    expect(spawn.calls[0]).toMatchObject({ command: "ngrok", args: ["version"] });
  });
});

describe("provider adapters", () => {
  it("starts, checks and turns off only its Tailscale Funnel route with fixed commands", async () => {
    const statusJson = JSON.stringify({
      Web: { "owner.tailnet-name.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:8931" } } } },
    });
    const execFile = fakeExecFile({
      "tailscale funnel status --json": { stdout: statusJson },
    });
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile });

    const started = await registry.start(PROVIDER_IDS.TAILSCALE_FUNNEL);
    const checked = await registry.status(PROVIDER_IDS.TAILSCALE_FUNNEL);
    const stopped = await registry.stop(PROVIDER_IDS.TAILSCALE_FUNNEL);

    expect(started).toMatchObject({ state: "running", endpoint: "wss://owner.tailnet-name.ts.net/" });
    expect(checked).toMatchObject({ state: "running", endpoint: "wss://owner.tailnet-name.ts.net/" });
    expect(stopped).toMatchObject({ state: "stopped", endpoint: null });
    expect(execFile.calls.map(({ command, args }) => [command, args])).toEqual([
      ["tailscale", ["funnel", "--bg", "--yes", "8931"]],
      ["tailscale", ["funnel", "status", "--json"]],
      ["tailscale", ["funnel", "status", "--json"]],
      ["tailscale", ["funnel", "--bg", "--yes", "8931", "off"]],
    ]);
  });

  it("turns off the Tailscale route when status parsing fails after activation", async () => {
    const execFile = fakeExecFile({
      "tailscale funnel status --json": { stdout: JSON.stringify({ Web: {} }) },
    });
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile });

    await expect(registry.start(PROVIDER_IDS.TAILSCALE_FUNNEL)).rejects.toMatchObject({ code: "endpoint_missing" });
    expect(execFile.calls.at(-1).args).toEqual(["funnel", "--bg", "--yes", "8931", "off"]);
  });

  it("passes the ngrok token only through env, parses JSON logs and cleans up", async () => {
    const token = "ngrok-secret-that-must-not-leak";
    const inheritedSecret = process.env.JC_CONNECTIVITY_TEST_SECRET;
    process.env.JC_CONNECTIVITY_TEST_SECRET = "unrelated-parent-secret";
    const spawn = fakeSpawn((child) => {
      child.stdout.write(`${JSON.stringify({ lvl: "info", msg: "started tunnel", url: "https://demo.ngrok-free.app" })}\n`);
    });
    let started;
    let stopped;
    try {
      const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });
      started = await registry.start(PROVIDER_IDS.NGROK, {
        env: { NGROK_AUTHTOKEN: token },
        startupTimeoutMs: 1_000,
      });
      stopped = await registry.stop(PROVIDER_IDS.NGROK);
    } finally {
      if (inheritedSecret === undefined) delete process.env.JC_CONNECTIVITY_TEST_SECRET;
      else process.env.JC_CONNECTIVITY_TEST_SECRET = inheritedSecret;
    }

    expect(spawn.calls[0].command).toBe("ngrok");
    expect(spawn.calls[0].args).toEqual(["http", "8931", "--log", "stdout", "--log-format", "json"]);
    expect(spawn.calls[0].options).toMatchObject({ shell: false, windowsHide: true });
    expect(spawn.calls[0].options.env.NGROK_AUTHTOKEN).toBe(token);
    expect(spawn.calls[0].options.env.JC_CONNECTIVITY_TEST_SECRET).toBeUndefined();
    expect(spawn.calls[0].args.join(" ")).not.toContain(token);
    expect(JSON.stringify(started)).not.toContain(token);
    expect(started).toMatchObject({ state: "running", endpoint: "wss://demo.ngrok-free.app/" });
    expect(stopped.state).toBe("stopped");
    expect(spawn.calls[0].child.signals).toEqual(["SIGTERM"]);
  });

  it("starts a temporary Cloudflare Quick Tunnel and labels the limitation", async () => {
    const spawn = fakeSpawn((child) => {
      child.stderr.write("Update docs: https://developers.cloudflare.com/cloudflare-one\n");
      child.stderr.write("Your quick Tunnel has been created! Visit https://random.trycloudflare.com\n");
    });
    const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });

    const result = await registry.start(PROVIDER_IDS.CLOUDFLARED_QUICK, { startupTimeoutMs: 1_000 });

    expect(spawn.calls[0].command).toBe("cloudflared");
    expect(spawn.calls[0].args).toEqual(["tunnel", "--url", "http://127.0.0.1:8931"]);
    expect(result).toMatchObject({
      state: "limited",
      endpoint: "wss://random.trycloudflare.com/",
      stability: "temporary",
    });
    await registry.stop(PROVIDER_IDS.CLOUDFLARED_QUICK);
  });

  it("starts a named Cloudflare tunnel with token in env and an explicit public endpoint", async () => {
    const token = "cloudflare-secret-that-must-not-leak";
    const spawn = fakeSpawn((child) => {
      child.stderr.write("INF Registered tunnel connection connIndex=0\n");
    });
    const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });

    const result = await registry.start(PROVIDER_IDS.CLOUDFLARED_NAMED, {
      env: { TUNNEL_TOKEN: token },
      endpoint: "wss://node.example.com",
      startupTimeoutMs: 1_000,
    });

    expect(spawn.calls[0].args).toEqual(["tunnel", "run"]);
    expect(spawn.calls[0].options.env.TUNNEL_TOKEN).toBe(token);
    expect(spawn.calls[0].args.join(" ")).not.toContain(token);
    expect(result).toMatchObject({ state: "running", endpoint: "wss://node.example.com/", stability: "account" });
    expect(JSON.stringify(result)).not.toContain(token);
    await registry.stop(PROVIDER_IDS.CLOUDFLARED_NAMED);
  });

  it("generates a bounded Nginx WebSocket config from a validated manual WSS endpoint", async () => {
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile: fakeExecFile() });
    const result = await registry.start(PROVIDER_IDS.MANUAL_NGINX, {
      endpoint: "wss://community.example.org",
    });

    expect(result).toMatchObject({
      state: "configuration_required",
      endpoint: "wss://community.example.org/",
      stability: "operator",
    });
    expect(result.nginxConfig).toContain("server_name community.example.org;");
    expect(result.nginxConfig).toContain("proxy_pass http://127.0.0.1:8931;");
    expect(result.nginxConfig).toContain("proxy_set_header Upgrade $http_upgrade;");
    expect(result.nginxConfig).not.toContain("wss://");
  });

  it.each([
    "ws://community.example.org",
    "wss://127.0.0.1",
    "wss://[::ffff:7f00:1]",
    "wss://localhost",
    "wss://user:password@community.example.org",
    "wss://community.example.org/?token=secret",
    "wss://community.example.org/socket",
  ])("rejects unsafe manual endpoint %s", async (endpoint) => {
    const registry = createProviderRegistry({ spawn: fakeSpawn(), execFile: fakeExecFile() });
    await expect(registry.start(PROVIDER_IDS.MANUAL_NGINX, { endpoint })).rejects.toThrow();
  });

  it("kills a provider that misses the startup deadline and never exposes its token", async () => {
    const token = "timeout-secret-that-must-not-leak";
    const spawn = fakeSpawn();
    const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });

    let error;
    try {
      await registry.start(PROVIDER_IDS.NGROK, {
        env: { NGROK_AUTHTOKEN: token },
        startupTimeoutMs: 250,
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).toMatchObject({ provider: "ngrok", code: "startup_timeout" });
    expect(error.message).not.toContain(token);
    expect(spawn.calls[0].child.signals).toEqual(["SIGTERM"]);
    await expect(registry.status(PROVIDER_IDS.NGROK)).resolves.toMatchObject({ state: "error", endpoint: null });
  });

  it("does not report running when a provider exits immediately after printing an endpoint", async () => {
    const spawn = fakeSpawn((child) => {
      child.stdout.write(`${JSON.stringify({ url: "https://demo.ngrok-free.app" })}\n`);
      child.exitCode = 1;
      child.emit("exit", 1);
    });
    const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });

    await expect(registry.start(PROVIDER_IDS.NGROK, {
      env: { NGROK_AUTHTOKEN: "token" },
      startupTimeoutMs: 1_000,
    })).rejects.toMatchObject({ code: "process_exited" });
    await expect(registry.status(PROVIDER_IDS.NGROK)).resolves.toMatchObject({ state: "error", endpoint: null });
  });

  it("rejects missing secrets and unsupported plain-data fields before spawning", async () => {
    const spawn = fakeSpawn();
    const registry = createProviderRegistry({ spawn, execFile: fakeExecFile() });

    await expect(registry.start(PROVIDER_IDS.NGROK, { env: {} })).rejects.toMatchObject({ code: "missing_secret" });
    await expect(registry.start(PROVIDER_IDS.CLOUDFLARED_NAMED, {
      env: { TUNNEL_TOKEN: "token" },
      endpoint: "wss://node.example.com",
      token: "must-not-be-an-option",
    })).rejects.toThrow(/not supported/);
    const reservedEnvironment = Object.create(null);
    reservedEnvironment.__proto__ = "pollution";
    await expect(registry.start(PROVIDER_IDS.NGROK, { env: reservedEnvironment })).rejects.toThrow(/reserved/);
    expect(spawn.calls).toHaveLength(0);
  });
});
