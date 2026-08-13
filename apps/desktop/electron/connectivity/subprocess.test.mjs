import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createSubprocessRunner } from "./subprocess.mjs";

describe("safe connectivity subprocess runner", () => {
  it("uses execFile with an argv array, shell disabled, timeout and bounded output", async () => {
    const calls = [];
    const execFile = (command, args, options, callback) => {
      calls.push({ command, args, options });
      queueMicrotask(() => callback(null, "version output", ""));
    };
    const runner = createSubprocessRunner({ spawn: () => {}, execFile });

    const result = await runner.run("provider-cli", ["status", "--json"], { timeoutMs: 800 });

    expect(result).toEqual({ stdout: "version output", stderr: "", exitCode: 0 });
    expect(calls[0]).toMatchObject({
      command: "provider-cli",
      args: ["status", "--json"],
      options: { shell: false, windowsHide: true, timeout: 800, encoding: "utf8" },
    });
    expect(calls[0].options.maxBuffer).toBe(128 * 1024);
  });

  it("uses spawn without a shell and terminates a long-running child", async () => {
    const calls = [];
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.exitCode = null;
    child.killed = false;
    child.kill = (signal) => {
      child.killed = true;
      child.exitCode = 0;
      child.emit("exit", 0, signal);
      return true;
    };
    const spawn = (command, args, options) => {
      calls.push({ command, args, options });
      return child;
    };
    const runner = createSubprocessRunner({ spawn });

    const running = runner.spawn("provider-cli", ["serve"], { env: { PATH: "/usr/bin" } });
    await runner.terminate(running);

    expect(calls[0]).toMatchObject({
      command: "provider-cli",
      args: ["serve"],
      options: { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
    });
    expect(child.killed).toBe(true);
  });

  it("returns sanitized command failures without stdout, stderr or argv", async () => {
    const execFile = (_command, _args, _options, callback) => {
      const error = Object.assign(new Error("secret stderr token=do-not-leak"), { code: 7 });
      queueMicrotask(() => callback(error, "secret stdout", "secret stderr"));
    };
    const runner = createSubprocessRunner({ spawn: () => {}, execFile });

    let error;
    try {
      await runner.run("provider-cli", ["--safe-flag"]);
    } catch (caught) {
      error = caught;
    }

    expect(error).toMatchObject({ code: "command_failed", command: "provider-cli", exitCode: 7 });
    expect(error.message).not.toMatch(/secret|safe-flag|stdout|stderr/);
  });

  it("rejects control characters before invoking a process", async () => {
    let invoked = false;
    const runner = createSubprocessRunner({
      spawn: () => {
        invoked = true;
      },
    });

    await expect(runner.run("provider-cli", ["ok\nmalicious"])).rejects.toThrow(/control characters/);
    expect(invoked).toBe(false);
  });
});
