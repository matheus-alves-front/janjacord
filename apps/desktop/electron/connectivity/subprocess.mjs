const DEFAULT_COMMAND_TIMEOUT_MS = 5_000;
const DEFAULT_TERMINATE_TIMEOUT_MS = 1_000;
const MAX_COMMAND_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 128 * 1024;

export class SubprocessError extends Error {
  constructor(code, command, exitCode = null, output = {}) {
    const suffix = Number.isInteger(exitCode) ? ` (exit ${exitCode})` : "";
    super(`Connectivity command '${command}' failed${suffix}.`);
    this.name = "SubprocessError";
    this.code = code;
    this.command = command;
    this.exitCode = Number.isInteger(exitCode) ? exitCode : null;
    this.stdout = output.stdout ?? "";
    this.stderr = output.stderr ?? "";
  }
}

function boundedTimeout(value, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > MAX_COMMAND_TIMEOUT_MS) {
    throw new TypeError(`timeoutMs must be an integer between 1 and ${MAX_COMMAND_TIMEOUT_MS}.`);
  }
  return value;
}

function validateInvocation(command, args) {
  if (typeof command !== "string" || !/^[A-Za-z0-9._/\\:-]{1,512}$/.test(command)) {
    throw new TypeError("command must be a safe executable name or path.");
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string" || arg.length > 8_192 || /[\u0000-\u001f\u007f]/.test(arg))) {
    throw new TypeError("args must be bounded strings without control characters.");
  }
}

function safeFailureCode(error) {
  if (error?.code === "ENOENT") return "not_found";
  if (error?.code === "ETIMEDOUT") return "timeout";
  if (error?.code === "ENOBUFS") return "output_limit";
  return "command_failed";
}

function appendBounded(chunks, chunk, currentBytes, child, command, reject) {
  const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
  const nextBytes = currentBytes + value.length;
  if (nextBytes > MAX_OUTPUT_BYTES) {
    child.kill?.("SIGKILL");
    reject(new SubprocessError("output_limit", command));
    return { bytes: nextBytes, accepted: false };
  }
  chunks.push(value);
  return { bytes: nextBytes, accepted: true };
}

export function createSubprocessRunner({ spawn, execFile } = {}) {
  if (typeof spawn !== "function") throw new TypeError("spawn dependency is required.");
  if (execFile !== undefined && typeof execFile !== "function") {
    throw new TypeError("execFile dependency must be a function when provided.");
  }

  function spawnProcess(command, args = [], { env } = {}) {
    validateInvocation(command, args);
    const child = spawn(command, [...args], {
      env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (!child || typeof child.once !== "function" || typeof child.kill !== "function") {
      throw new SubprocessError("spawn_failed", command);
    }
    return child;
  }

  function runWithExecFile(command, args, { env, timeoutMs }) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (callback) => (value) => {
        if (settled) return;
        settled = true;
        callback(value);
      };
      const fail = finish((error) => {
        reject(new SubprocessError(safeFailureCode(error), command, error?.code === "ETIMEDOUT" ? null : error?.code, {
          stdout: String(error?.subprocessStdout ?? ""),
          stderr: String(error?.subprocessStderr ?? ""),
        }));
      });
      const succeed = finish(resolve);

      try {
        execFile(command, [...args], {
          env,
          shell: false,
          windowsHide: true,
          timeout: timeoutMs,
          maxBuffer: MAX_OUTPUT_BYTES,
          encoding: "utf8",
        }, (error, stdout = "", stderr = "") => {
          if (error) {
            fail(Object.assign(error, { subprocessStdout: String(stdout).slice(0, MAX_OUTPUT_BYTES), subprocessStderr: String(stderr).slice(0, MAX_OUTPUT_BYTES) }));
            return;
          }
          succeed({ stdout: String(stdout), stderr: String(stderr), exitCode: 0 });
        });
      } catch (error) {
        fail(error);
      }
    });
  }

  function runWithSpawn(command, args, { env, timeoutMs }) {
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawnProcess(command, args, { env });
      } catch (error) {
        reject(error);
        return;
      }

      const stdout = [];
      const stderr = [];
      let outputBytes = 0;
      let settled = false;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        callback(value);
      };
      const collect = (target) => (chunk) => {
        if (settled) return;
        const result = appendBounded(target, chunk, outputBytes, child, command, (error) => finish(reject, error));
        outputBytes = result.bytes;
      };

      child.stdout?.on("data", collect(stdout));
      child.stderr?.on("data", collect(stderr));
      child.once("error", (error) => finish(reject, new SubprocessError(safeFailureCode(error), command)));
      child.once("exit", (code) => {
        if (code !== 0) {
          finish(reject, new SubprocessError("command_failed", command, code, {
            stdout: Buffer.concat(stdout).toString("utf8").slice(0, MAX_OUTPUT_BYTES),
            stderr: Buffer.concat(stderr).toString("utf8").slice(0, MAX_OUTPUT_BYTES),
          }));
          return;
        }
        finish(resolve, {
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
          exitCode: 0,
        });
      });

      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(reject, new SubprocessError("timeout", command));
      }, timeoutMs);
      timer.unref?.();
    });
  }

  async function run(command, args = [], options = {}) {
    validateInvocation(command, args);
    const timeoutMs = boundedTimeout(options.timeoutMs, DEFAULT_COMMAND_TIMEOUT_MS);
    if (execFile) return runWithExecFile(command, args, { env: options.env, timeoutMs });
    return runWithSpawn(command, args, { env: options.env, timeoutMs });
  }

  async function terminate(child, timeoutMs = DEFAULT_TERMINATE_TIMEOUT_MS) {
    if (!child || child.exitCode !== null || child.killed) return;
    const bounded = boundedTimeout(timeoutMs, DEFAULT_TERMINATE_TIMEOUT_MS);
    await new Promise((resolve) => {
      let settled = false;
      let timer;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      child.once("exit", finish);
      child.once("error", finish);
      try {
        child.kill("SIGTERM");
      } catch {
        finish();
        return;
      }
      timer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // The process may have exited between the state check and the signal.
        }
        finish();
      }, bounded);
      timer.unref?.();
    });
  }

  return Object.freeze({ run, spawn: spawnProcess, terminate });
}
