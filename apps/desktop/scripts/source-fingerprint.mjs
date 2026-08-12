#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

export const SOURCE_MANIFEST_FILENAME = "janjacord-source-manifest.json";
export const SOURCE_MANIFEST_KIND = "janjacord-source-provenance";
export const SOURCE_MANIFEST_SCHEMA_VERSION = 3;
export const SOURCE_SNAPSHOT_KIND = "janjacord-recoverable-source-snapshot";
export const SOURCE_SNAPSHOT_SCHEMA_VERSION = 1;
export const SOURCE_SNAPSHOT_METADATA_FILENAME = "janjacord-source-snapshot.json";
export const SOURCE_SNAPSHOT_CONTENT_ROOT = "source";
export const RUNTIME_BUILD_ROOT_WORKSPACE = "@janjacord/desktop";
export const RUNTIME_BUILD_COMMAND = ["pnpm", "--filter", `${RUNTIME_BUILD_ROOT_WORKSPACE}...`, "run", "build"];
export const PRIVILEGED_PAYLOAD_SPECS = Object.freeze([
  Object.freeze({ sourcePath: "apps/desktop/electron/main.mjs", asarPath: "electron/main.mjs" }),
  Object.freeze({ sourcePath: "apps/desktop/electron/preload.cjs", asarPath: "electron/preload.cjs" }),
]);

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const workspaceParentDirectories = ["apps", "packages"];
const safeRuntimeOutputRoots = new Set(["dist", "pkg"]);
const sourceDirectoryRoots = new Set([".github", "apps", "docs", "infra", "packages", "scripts"]);
const sourceRootFiles = new Set([
  ".gitignore",
  "README.md",
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "tsconfig.base.json",
  "turbo.json",
]);
const sourcePathOverrides = new Set([
  "apps/desktop/build/icon.png",
  "apps/desktop/build/icon.svg",
]);
const excludedSourcePathSegments = new Set([".git", ".turbo", "build", "coverage", "dist", "node_modules", "out", "release", "target"]);
const sensitiveBasenames = new Set([
  ".npmrc",
  ".pypirc",
  "credential",
  "auth.json",
  "credentials.json",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa",
  "secrets.json",
  "secret",
  "service-account.json",
  "session.json",
  "token",
  "tokens.json",
  "vault",
  "vault.json",
]);
const sensitiveDirectorySegments = new Set([".secrets", "backup", "backups", "user-data", "userdata"]);
const sensitiveExtensions = new Set([
  ".bak",
  ".backup",
  ".db",
  ".db3",
  ".dump",
  ".jks",
  ".key",
  ".keystore",
  ".p12",
  ".pfx",
  ".pem",
  ".secret",
  ".sqlite",
  ".sqlite3",
  ".token",
  ".vault",
]);
const tarBlockSize = 512;

function fail(message) {
  throw new Error(message);
}

function runGit(repoRoot, args, options = {}) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: options.encoding ?? "buffer",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.error) fail(`git ${args.join(" ")} could not run: ${result.error.message}`);
  if (result.status !== 0 && !options.allowFailure) {
    const detail = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : result.stderr;
    fail(`git ${args.join(" ")} failed: ${String(detail ?? "").trim()}`);
  }
  return result;
}

function decodeGitPath(rawPath) {
  let decoded;
  try {
    decoded = utf8Decoder.decode(rawPath);
  } catch {
    fail("source fingerprint requires Git paths to be valid UTF-8");
  }
  if (!Buffer.from(decoded, "utf8").equals(rawPath)) fail(`Git path did not round-trip as UTF-8: ${decoded}`);
  if (decoded === "" || decoded.includes("\0") || path.isAbsolute(decoded)) fail(`invalid Git path: ${decoded}`);
  return decoded;
}

function nulSeparatedPaths(buffer) {
  const paths = [];
  let start = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] !== 0) continue;
    if (index > start) paths.push(decodeGitPath(buffer.subarray(start, index)));
    start = index + 1;
  }
  if (start !== buffer.length) fail("Git returned a path list without a trailing NUL");
  return paths;
}

function comparePaths(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function statIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}

function hashFileStable(file, before, securityLabel) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let scanCarry = Buffer.alloc(0);
  const descriptor = openSync(file, "r");
  try {
    for (;;) {
      const bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (securityLabel) {
        const scan = Buffer.concat([scanCarry, chunk]);
        assertContentHasNoPrivateKey(scan, securityLabel);
        scanCarry = Buffer.from(scan.subarray(Math.max(0, scan.length - 128)));
      }
    }
  } finally {
    closeSync(descriptor);
  }
  const after = lstatSync(file, { bigint: true });
  if (statIdentity(before) !== statIdentity(after)) fail(`source changed while fingerprinting: ${file}`);
  return hash.digest("hex");
}

function portablePath(value) {
  return value.split(path.sep).join("/");
}

function assertPortableRelativePath(value, label) {
  if (typeof value !== "string" || value === "" || value.includes("\\") || value.startsWith("/") || /[\0-\x1f\x7f]/.test(value)) {
    fail(`${label} must be a non-empty portable relative path`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    fail(`${label} contains an unsafe path segment`);
  }
  return value;
}

function isExcludedSourcePath(relativePath) {
  const segments = relativePath.split("/");
  if (!sourceRootFiles.has(relativePath) && !sourceDirectoryRoots.has(segments[0])) return true;
  if (sourcePathOverrides.has(relativePath)) return false;
  return segments.some((segment) => excludedSourcePathSegments.has(segment));
}

function assertSourcePathIsNotSensitive(relativePath) {
  const basename = path.posix.basename(relativePath).toLowerCase();
  const extension = path.posix.extname(basename);
  const directorySegments = relativePath.toLowerCase().split("/").slice(0, -1);
  const envFile = basename === ".env" || (basename.startsWith(".env.") && !/^\.env\.(?:example|sample|template)$/.test(basename));
  const sensitiveDataDirectory = directorySegments.some((segment) => sensitiveDirectorySegments.has(segment));
  const databaseSidecar = /\.(?:db|db3|sqlite|sqlite3)-(?:journal|shm|wal)$/.test(basename);
  const backupArchive = /(?:^|[._-])backup(?:s)?(?:[._-]|$)/.test(basename)
    && /\.(?:7z|dump|gz|tar|tgz|xz|zip|zst)$/.test(basename);
  const namedSecretArtifact = /(?:^|[._-])(?:credential|secret|session|token|vault)s?(?:[._-]|$)/.test(basename)
    && /\.(?:bin|dat|db|json|sqlite|sqlite3|txt|yaml|yml)$/.test(basename);
  if (envFile || sensitiveDataDirectory || databaseSidecar || backupArchive || namedSecretArtifact || sensitiveBasenames.has(basename) || sensitiveExtensions.has(extension)) {
    fail(`refusing to fingerprint a potential secret file: ${relativePath}`);
  }
}

function assertContentHasNoPrivateKey(content, relativePath) {
  const privateKeyBlockStart = /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{20,}/;
  if (privateKeyBlockStart.test(content.toString("latin1"))) {
    fail(`refusing to fingerprint private-key material: ${relativePath}`);
  }
}

export function validatePrivilegedPayloadAttestation(payloads, label = "privileged payload attestation") {
  if (!Array.isArray(payloads) || payloads.length !== PRIVILEGED_PAYLOAD_SPECS.length) {
    fail(`${label} must contain exactly ${PRIVILEGED_PAYLOAD_SPECS.length} payloads`);
  }
  for (let index = 0; index < PRIVILEGED_PAYLOAD_SPECS.length; index += 1) {
    const expected = PRIVILEGED_PAYLOAD_SPECS[index];
    const payload = payloads[index];
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail(`${label} has an invalid payload record`);
    assertPortableRelativePath(payload.sourcePath, `${label} sourcePath`);
    assertPortableRelativePath(payload.asarPath, `${label} asarPath`);
    if (payload.sourcePath !== expected.sourcePath || payload.asarPath !== expected.asarPath) {
      fail(`${label} payload ${index} must attest ${expected.sourcePath} as ${expected.asarPath}`);
    }
    if (!Number.isSafeInteger(payload.size) || payload.size < 1) fail(`${label} payload ${payload.asarPath} has invalid size`);
    if (!/^[a-f0-9]{64}$/.test(payload.sha256)) fail(`${label} payload ${payload.asarPath} has invalid SHA-256`);
  }
  return payloads;
}

export function computePrivilegedPayloadAttestation(repoRoot) {
  const root = realpathSync(repoRoot);
  const payloads = PRIVILEGED_PAYLOAD_SPECS.map(({ sourcePath, asarPath }) => {
    const absolute = path.resolve(root, ...sourcePath.split("/"));
    if (!absolute.startsWith(`${root}${path.sep}`)) fail(`privileged payload escapes the repository: ${sourcePath}`);
    let before;
    try {
      before = lstatSync(absolute, { bigint: true });
    } catch (error) {
      if (error?.code === "ENOENT") fail(`privileged payload is missing: ${sourcePath}`);
      throw error;
    }
    if (!before.isFile()) fail(`privileged payload is not a regular file: ${sourcePath}`);
    const size = Number(before.size);
    if (!Number.isSafeInteger(size) || size < 1) fail(`privileged payload has invalid size: ${sourcePath}`);
    return { sourcePath, asarPath, size, sha256: hashFileStable(absolute, before) };
  });
  return validatePrivilegedPayloadAttestation(payloads);
}

function readJson(file, label) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function collectEntrypointStrings(value, entries) {
  if (typeof value === "string") {
    entries.push(value);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const nested of Object.values(value)) collectEntrypointStrings(nested, entries);
}

function runtimeOutputRoots(packageJson, isRootWorkspace) {
  if (isRootWorkspace) return ["dist"];
  const entrypoints = [];
  collectEntrypointStrings(packageJson.main, entrypoints);
  collectEntrypointStrings(packageJson.module, entrypoints);
  collectEntrypointStrings(packageJson.exports, entrypoints);
  const roots = new Set();
  for (const entrypoint of entrypoints) {
    const normalized = entrypoint.replace(/^\.\//, "");
    const root = normalized.split("/")[0];
    if (safeRuntimeOutputRoots.has(root)) roots.add(root);
  }
  if (roots.size === 0) fail(`${packageJson.name} has no supported compiled runtime output in main/module/exports`);
  return [...roots].sort(comparePaths);
}

function loadWorkspacePackages(workspaceRoot) {
  const packagesByName = new Map();
  for (const parent of workspaceParentDirectories) {
    const parentPath = path.join(workspaceRoot, parent);
    if (!existsSync(parentPath)) continue;
    for (const entry of readdirSync(parentPath, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const packagePath = path.join(parentPath, entry.name, "package.json");
      if (!existsSync(packagePath)) continue;
      const packageJson = readJson(packagePath, portablePath(path.relative(workspaceRoot, packagePath)));
      if (typeof packageJson.name !== "string" || packageJson.name === "") fail(`${packagePath} has no package name`);
      if (packagesByName.has(packageJson.name)) fail(`duplicate workspace package name: ${packageJson.name}`);
      packagesByName.set(packageJson.name, {
        name: packageJson.name,
        packageJson,
        packagePath: portablePath(path.relative(workspaceRoot, path.dirname(packagePath))),
      });
    }
  }
  return packagesByName;
}

function workspaceRuntimeDependencies(workspacePackage, packagesByName) {
  const dependencies = {
    ...(workspacePackage.packageJson.dependencies ?? {}),
    ...(workspacePackage.packageJson.optionalDependencies ?? {}),
  };
  return Object.entries(dependencies)
    .filter(([name, specifier]) => packagesByName.has(name) && typeof specifier === "string" && specifier.startsWith("workspace:"))
    .map(([name]) => name)
    .sort(comparePaths);
}

export function discoverRuntimeWorkspacePlan(workspaceRoot) {
  const root = realpathSync(workspaceRoot);
  const packagesByName = loadWorkspacePackages(root);
  if (!packagesByName.has(RUNTIME_BUILD_ROOT_WORKSPACE)) fail(`runtime root workspace ${RUNTIME_BUILD_ROOT_WORKSPACE} was not found`);

  const selected = new Set();
  const pending = [RUNTIME_BUILD_ROOT_WORKSPACE];
  while (pending.length > 0) {
    const name = pending.pop();
    if (selected.has(name)) continue;
    selected.add(name);
    const workspacePackage = packagesByName.get(name);
    for (const dependency of workspaceRuntimeDependencies(workspacePackage, packagesByName)) pending.push(dependency);
  }

  return [...selected].sort(comparePaths).map((name) => {
    const workspacePackage = packagesByName.get(name);
    if (typeof workspacePackage.packageJson.scripts?.build !== "string" || workspacePackage.packageJson.scripts.build === "") {
      fail(`runtime workspace ${name} has no build script`);
    }
    return {
      name,
      packagePath: workspacePackage.packagePath,
      outputRoots: runtimeOutputRoots(workspacePackage.packageJson, name === RUNTIME_BUILD_ROOT_WORKSPACE),
    };
  });
}

export function cleanGeneratedRuntimeOutputs(workspaceRoot, plan) {
  const root = realpathSync(workspaceRoot);
  for (const workspace of plan) {
    for (const outputRoot of workspace.outputRoots) {
      if (!safeRuntimeOutputRoots.has(outputRoot)) fail(`refusing to clean unsupported runtime output root: ${outputRoot}`);
      const relativeOutput = `${workspace.packagePath}/${outputRoot}`;
      const tracked = runGit(root, ["ls-files", "-z", "--", relativeOutput]).stdout;
      if (tracked.length > 0) continue;
      rmSync(path.join(root, ...relativeOutput.split("/")), { recursive: true, force: true });
    }
  }
}

function isRuntimePayload(relativePath) {
  const name = path.posix.basename(relativePath);
  if (name === SOURCE_MANIFEST_FILENAME) return false;
  if (name.endsWith(".map") || name.includes(".test.")) return false;
  if (/\.d\.(?:ts|mts|cts)$/.test(name)) return false;
  return true;
}

function listRuntimePayloadFiles(root, relativeDirectory) {
  const absoluteDirectory = path.join(root, ...relativeDirectory.split("/"));
  if (!existsSync(absoluteDirectory) || !statSync(absoluteDirectory).isDirectory()) {
    fail(`runtime build did not produce ${relativeDirectory}`);
  }
  const files = [];
  const visit = (absolute, relative) => {
    for (const entry of readdirSync(absolute, { withFileTypes: true })) {
      const childAbsolute = path.join(absolute, entry.name);
      const childRelative = `${relative}/${entry.name}`;
      if (entry.isDirectory()) visit(childAbsolute, childRelative);
      else if (entry.isFile() && isRuntimePayload(childRelative)) files.push(childRelative);
      else if (entry.isSymbolicLink()) fail(`runtime payload output may not contain symlinks: ${childRelative}`);
    }
  };
  visit(absoluteDirectory, relativeDirectory);
  return files.sort(comparePaths);
}

export function computeRuntimeBuildAttestation(workspaceRoot, plan = discoverRuntimeWorkspacePlan(workspaceRoot)) {
  const root = realpathSync(workspaceRoot);
  const payloads = [];
  for (const workspace of plan) {
    for (const outputRoot of workspace.outputRoots) {
      const relativeOutput = `${workspace.packagePath}/${outputRoot}`;
      for (const sourcePath of listRuntimePayloadFiles(root, relativeOutput)) {
        const suffix = sourcePath.slice(workspace.packagePath.length + 1);
        const asarPath = workspace.name === RUNTIME_BUILD_ROOT_WORKSPACE
          ? suffix
          : `node_modules/${workspace.name}/${suffix}`;
        const absolute = path.join(root, ...sourcePath.split("/"));
        const before = lstatSync(absolute, { bigint: true });
        const size = Number(before.size);
        if (!Number.isSafeInteger(size)) fail(`runtime payload is too large to attest safely: ${sourcePath}`);
        payloads.push({
          workspace: workspace.name,
          sourcePath,
          asarPath,
          size,
          sha256: hashFileStable(absolute, before),
        });
      }
    }
  }
  payloads.sort((left, right) => comparePaths(left.asarPath, right.asarPath));
  const runtimeBuild = {
    command: [...RUNTIME_BUILD_COMMAND],
    rootWorkspace: RUNTIME_BUILD_ROOT_WORKSPACE,
    payloadHashAlgorithm: "sha256",
    workspaces: plan.map((workspace) => ({
      name: workspace.name,
      packagePath: workspace.packagePath,
      outputRoots: [...workspace.outputRoots],
    })),
    payloads,
  };
  return validateRuntimeBuildAttestation(runtimeBuild);
}

export function validateRuntimeBuildAttestation(runtimeBuild, label = "runtime build attestation") {
  if (!runtimeBuild || typeof runtimeBuild !== "object" || Array.isArray(runtimeBuild)) fail(`${label} is not an object`);
  if (JSON.stringify(runtimeBuild.command) !== JSON.stringify(RUNTIME_BUILD_COMMAND)) fail(`${label} has an unexpected build command`);
  if (runtimeBuild.rootWorkspace !== RUNTIME_BUILD_ROOT_WORKSPACE) fail(`${label} has an unexpected root workspace`);
  if (runtimeBuild.payloadHashAlgorithm !== "sha256") fail(`${label} has an unsupported payload hash algorithm`);
  if (!Array.isArray(runtimeBuild.workspaces) || runtimeBuild.workspaces.length < 2) fail(`${label} has no runtime workspace graph`);
  if (!Array.isArray(runtimeBuild.payloads) || runtimeBuild.payloads.length < runtimeBuild.workspaces.length) fail(`${label} has too few compiled payloads`);

  const workspaces = new Map();
  let previousWorkspaceName = "";
  for (const workspace of runtimeBuild.workspaces) {
    if (!workspace || typeof workspace !== "object" || Array.isArray(workspace)) fail(`${label} has an invalid workspace record`);
    if (typeof workspace.name !== "string" || workspace.name === "") fail(`${label} has an invalid workspace name`);
    if (previousWorkspaceName && comparePaths(previousWorkspaceName, workspace.name) >= 0) fail(`${label} workspace records are not uniquely sorted`);
    previousWorkspaceName = workspace.name;
    assertPortableRelativePath(workspace.packagePath, `${label} ${workspace.name} packagePath`);
    if (!Array.isArray(workspace.outputRoots) || workspace.outputRoots.length < 1) fail(`${label} ${workspace.name} has no output roots`);
    for (const outputRoot of workspace.outputRoots) {
      if (!safeRuntimeOutputRoots.has(outputRoot)) fail(`${label} ${workspace.name} has unsupported output root ${outputRoot}`);
    }
    workspaces.set(workspace.name, workspace);
  }
  if (!workspaces.has(RUNTIME_BUILD_ROOT_WORKSPACE)) fail(`${label} omits the root workspace`);

  const sourcePaths = new Set();
  const asarPaths = new Set();
  const payloadCountByWorkspace = new Map();
  let previousAsarPath = "";
  for (const payload of runtimeBuild.payloads) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail(`${label} has an invalid payload record`);
    const workspace = workspaces.get(payload.workspace);
    if (!workspace) fail(`${label} payload references unknown workspace ${payload.workspace}`);
    assertPortableRelativePath(payload.sourcePath, `${label} payload sourcePath`);
    assertPortableRelativePath(payload.asarPath, `${label} payload asarPath`);
    if (previousAsarPath && comparePaths(previousAsarPath, payload.asarPath) >= 0) fail(`${label} payload records are not uniquely sorted`);
    previousAsarPath = payload.asarPath;
    if (sourcePaths.has(payload.sourcePath) || asarPaths.has(payload.asarPath)) fail(`${label} contains duplicate payload paths`);
    sourcePaths.add(payload.sourcePath);
    asarPaths.add(payload.asarPath);
    const matchingRoot = workspace.outputRoots.find((outputRoot) => payload.sourcePath.startsWith(`${workspace.packagePath}/${outputRoot}/`));
    if (!matchingRoot) fail(`${label} payload sourcePath is outside ${payload.workspace} outputs`);
    const suffix = payload.sourcePath.slice(workspace.packagePath.length + 1);
    const expectedAsarPath = payload.workspace === RUNTIME_BUILD_ROOT_WORKSPACE
      ? suffix
      : `node_modules/${payload.workspace}/${suffix}`;
    if (payload.asarPath !== expectedAsarPath) fail(`${label} payload has inconsistent ASAR path ${payload.asarPath}`);
    if (!Number.isSafeInteger(payload.size) || payload.size < 0) fail(`${label} payload ${payload.asarPath} has invalid size`);
    if (!/^[a-f0-9]{64}$/.test(payload.sha256)) fail(`${label} payload ${payload.asarPath} has invalid SHA-256`);
    payloadCountByWorkspace.set(payload.workspace, (payloadCountByWorkspace.get(payload.workspace) ?? 0) + 1);
  }
  for (const workspaceName of workspaces.keys()) {
    if (!payloadCountByWorkspace.has(workspaceName)) fail(`${label} has no compiled payload for ${workspaceName}`);
  }
  return runtimeBuild;
}

function sourceRecord(repoRoot, relativePath, source) {
  assertPortableRelativePath(relativePath, "source path");
  assertSourcePathIsNotSensitive(relativePath);
  const absolutePath = path.resolve(repoRoot, relativePath);
  if (absolutePath !== repoRoot && !absolutePath.startsWith(`${repoRoot}${path.sep}`)) {
    fail(`Git path escapes the repository: ${relativePath}`);
  }
  let before;
  try {
    before = lstatSync(absolutePath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT" && source === "tracked") return { source, path: relativePath, type: "missing" };
    if (error?.code === "ENOENT") fail(`untracked source disappeared while fingerprinting: ${relativePath}`);
    throw error;
  }

  if (before.isFile()) {
    return {
      source,
      path: relativePath,
      type: "file",
      executable: (before.mode & 0o111n) !== 0n,
      size: before.size.toString(),
      sha256: hashFileStable(absolutePath, before, relativePath),
    };
  }
  if (before.isSymbolicLink()) {
    const target = readlinkSync(absolutePath, { encoding: "buffer" });
    const after = lstatSync(absolutePath, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail(`symlink changed while fingerprinting: ${relativePath}`);
    return {
      source,
      path: relativePath,
      type: "symlink",
      targetBase64: target.toString("base64"),
    };
  }
  fail(`unsupported source entry type (submodules and special files are not accepted): ${relativePath}`);
}

function fingerprintRecords(records) {
  const hash = createHash("sha256");
  hash.update("janjacord-source-fingerprint\0v2-source-root-allowlist\0", "utf8");
  for (const record of records) {
    hash.update(JSON.stringify(record), "utf8");
    hash.update("\0", "utf8");
  }
  return hash.digest("hex");
}

export function computeSourceSnapshot(repoRoot) {
  const root = realpathSync(repoRoot);
  const discoveredRoot = realpathSync(runGit(root, ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).stdout.trim());
  if (root !== discoveredRoot) fail(`source root must be the Git toplevel: expected ${discoveredRoot}, got ${root}`);

  const headBeforeResult = runGit(root, ["rev-parse", "--verify", "HEAD"], { encoding: "utf8", allowFailure: true });
  const headBefore = headBeforeResult.status === 0 ? headBeforeResult.stdout.trim() : "UNBORN";
  const statusBefore = runGit(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no"]).stdout;
  const tracked = nulSeparatedPaths(runGit(root, ["ls-files", "--cached", "-z"]).stdout);
  const untracked = nulSeparatedPaths(runGit(root, ["ls-files", "--others", "--exclude-standard", "-z"]).stdout);

  const seen = new Set();
  const entries = [];
  for (const [source, paths] of [["tracked", tracked], ["untracked", untracked]]) {
    for (const relativePath of paths) {
      if (isExcludedSourcePath(relativePath)) continue;
      if (seen.has(relativePath)) fail(`source path appears more than once: ${relativePath}`);
      seen.add(relativePath);
      entries.push(sourceRecord(root, relativePath, source));
    }
  }
  entries.sort((left, right) => comparePaths(left.path, right.path));
  const privilegedPayloads = computePrivilegedPayloadAttestation(root);

  const headAfterResult = runGit(root, ["rev-parse", "--verify", "HEAD"], { encoding: "utf8", allowFailure: true });
  const headAfter = headAfterResult.status === 0 ? headAfterResult.stdout.trim() : "UNBORN";
  const statusAfter = runGit(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no"]).stdout;
  if (headBefore !== headAfter || !statusBefore.equals(statusAfter)) fail("Git source state changed while fingerprinting");

  return {
    fingerprint: fingerprintRecords(entries),
    head: headAfter,
    dirty: statusAfter.length > 0,
    entryCount: entries.length,
    entries,
    privilegedPayloads,
  };
}

export function assertSourceSnapshotUnchanged(expected, actual, phase) {
  for (const field of ["fingerprint", "head", "dirty", "entryCount"]) {
    if (expected[field] !== actual[field]) {
      fail(`source changed during ${phase}: ${field} was ${expected[field]} and is now ${actual[field]}`);
    }
  }
  if (JSON.stringify(expected.privilegedPayloads) !== JSON.stringify(actual.privilegedPayloads)) {
    fail(`source changed during ${phase}: privileged Electron payload attestation changed`);
  }
}

function validateSourceEntries(entries, label = "source snapshot entries") {
  if (!Array.isArray(entries) || entries.length < 1) fail(`${label} must be a non-empty array`);
  let previousPath = "";
  for (const record of entries) {
    if (!record || typeof record !== "object" || Array.isArray(record)) fail(`${label} has an invalid record`);
    if (record.source !== "tracked" && record.source !== "untracked") fail(`${label} has an invalid source marker`);
    assertPortableRelativePath(record.path, `${label} path`);
    if (isExcludedSourcePath(record.path)) fail(`${label} contains excluded generated/evidence content: ${record.path}`);
    assertSourcePathIsNotSensitive(record.path);
    if (previousPath && comparePaths(previousPath, record.path) >= 0) fail(`${label} paths are not uniquely sorted`);
    previousPath = record.path;
    if (record.type === "file") {
      if (Object.keys(record).sort().join(",") !== "executable,path,sha256,size,source,type") fail(`${label} file ${record.path} has unexpected fields`);
      if (typeof record.executable !== "boolean") fail(`${label} file ${record.path} has an invalid executable marker`);
      if (typeof record.size !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(record.size)) fail(`${label} file ${record.path} has an invalid size`);
      if (!/^[a-f0-9]{64}$/.test(record.sha256)) fail(`${label} file ${record.path} has an invalid SHA-256`);
    } else if (record.type === "symlink") {
      if (Object.keys(record).sort().join(",") !== "path,source,targetBase64,type") fail(`${label} symlink ${record.path} has unexpected fields`);
      if (typeof record.targetBase64 !== "string" || Buffer.from(record.targetBase64, "base64").toString("base64") !== record.targetBase64) {
        fail(`${label} symlink ${record.path} has an invalid target`);
      }
      if (Buffer.from(record.targetBase64, "base64").length > 100) fail(`${label} symlink ${record.path} target exceeds the USTAR limit`);
    } else if (record.type === "missing") {
      if (Object.keys(record).sort().join(",") !== "path,source,type") fail(`${label} missing record ${record.path} has unexpected fields`);
      if (record.source !== "tracked") fail(`${label} contains a missing untracked path: ${record.path}`);
    } else {
      fail(`${label} has unsupported type ${record.type} for ${record.path}`);
    }
  }
  return entries;
}

function sourceSnapshotFilename(fingerprint) {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) fail("source snapshot filename requires a valid fingerprint");
  return `JanjaCord-source-${fingerprint}.tar`;
}

function canonicalJson(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeAll(descriptor, content) {
  let offset = 0;
  while (offset < content.length) offset += writeSync(descriptor, content, offset, content.length - offset);
}

function tarPathFields(portableName) {
  const bytes = Buffer.from(portableName, "utf8");
  if (bytes.length <= 100) return { name: portableName, prefix: "" };
  for (let slash = portableName.lastIndexOf("/"); slash > 0; slash = portableName.lastIndexOf("/", slash - 1)) {
    const prefix = portableName.slice(0, slash);
    const name = portableName.slice(slash + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) return { name, prefix };
  }
  fail(`source snapshot path exceeds the USTAR limit: ${portableName}`);
}

function writeTarString(header, offset, length, value, label) {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length > length) fail(`${label} exceeds the USTAR field limit`);
  encoded.copy(header, offset);
}

function writeTarOctal(header, offset, length, value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} is not a safe non-negative integer`);
  const encoded = value.toString(8).padStart(length - 1, "0");
  if (encoded.length > length - 1) fail(`${label} exceeds the USTAR numeric limit`);
  writeTarString(header, offset, length - 1, encoded, label);
}

function createTarHeader(entry) {
  const header = Buffer.alloc(tarBlockSize);
  const { name, prefix } = tarPathFields(entry.path);
  writeTarString(header, 0, 100, name, "USTAR name");
  writeTarOctal(header, 100, 8, entry.mode, "USTAR mode");
  writeTarOctal(header, 108, 8, 0, "USTAR uid");
  writeTarOctal(header, 116, 8, 0, "USTAR gid");
  writeTarOctal(header, 124, 12, entry.size, "USTAR size");
  writeTarOctal(header, 136, 12, 0, "USTAR mtime");
  header.fill(0x20, 148, 156);
  header[156] = entry.type === "file" ? 0x30 : entry.type === "symlink" ? 0x32 : 0x35;
  if (entry.type === "symlink") {
    const target = Buffer.from(entry.targetBase64, "base64");
    if (target.includes(0)) fail(`symlink target contains NUL: ${entry.path}`);
    target.copy(header, 157);
  }
  writeTarString(header, 257, 6, "ustar", "USTAR magic");
  writeTarString(header, 263, 2, "00", "USTAR version");
  writeTarString(header, 345, 155, prefix, "USTAR prefix");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeTarString(header, 148, 6, checksum.toString(8).padStart(6, "0"), "USTAR checksum");
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function archiveDirectoryEntries(records) {
  const directories = new Set([SOURCE_SNAPSHOT_CONTENT_ROOT]);
  for (const record of records) {
    if (record.type === "missing") continue;
    const segments = `${SOURCE_SNAPSHOT_CONTENT_ROOT}/${record.path}`.split("/");
    for (let index = 1; index < segments.length; index += 1) directories.add(segments.slice(0, index).join("/"));
  }
  return [...directories].map((directory) => ({ path: directory, type: "directory", mode: 0o755, size: 0 }));
}

function assertSourceRecordStillMatches(repoRoot, record) {
  const current = sourceRecord(repoRoot, record.path, record.source);
  if (JSON.stringify(current) !== JSON.stringify(record)) fail(`source changed while creating recoverable snapshot: ${record.path}`);
}

function writeSourceFilePayload(descriptor, repoRoot, record) {
  assertSourceRecordStillMatches(repoRoot, record);
  const absolute = path.join(repoRoot, ...record.path.split("/"));
  const sourceDescriptor = openSync(absolute, "r");
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let written = 0;
  let scanCarry = Buffer.alloc(0);
  try {
    for (;;) {
      const bytesRead = readSync(sourceDescriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      const scan = Buffer.concat([scanCarry, chunk]);
      assertContentHasNoPrivateKey(scan, record.path);
      scanCarry = Buffer.from(scan.subarray(Math.max(0, scan.length - 128)));
      writeAll(descriptor, chunk);
      written += bytesRead;
    }
  } finally {
    closeSync(sourceDescriptor);
  }
  if (String(written) !== record.size || hash.digest("hex") !== record.sha256) {
    fail(`source content changed while creating recoverable snapshot: ${record.path}`);
  }
  assertSourceRecordStillMatches(repoRoot, record);
  const padding = (tarBlockSize - (written % tarBlockSize)) % tarBlockSize;
  if (padding) writeAll(descriptor, Buffer.alloc(padding));
}

export function validateSourceSnapshotDescriptor(descriptor, label = "source snapshot descriptor") {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) fail(`${label} is not an object`);
  if (descriptor.format !== "ustar") fail(`${label} has unsupported format`);
  if (!/^[a-f0-9]{64}$/.test(descriptor.fingerprint)) fail(`${label} has an invalid fingerprint`);
  if (descriptor.filename !== sourceSnapshotFilename(descriptor.fingerprint)) fail(`${label} filename is not bound to its fingerprint`);
  if (descriptor.digestFilename !== `${descriptor.filename}.sha256`) fail(`${label} has an inconsistent digest filename`);
  if (!/^[a-f0-9]{64}$/.test(descriptor.sha256)) fail(`${label} has an invalid archive SHA-256`);
  if (descriptor.metadataFilename !== SOURCE_SNAPSHOT_METADATA_FILENAME) fail(`${label} has an unexpected metadata filename`);
  if (descriptor.contentRoot !== SOURCE_SNAPSHOT_CONTENT_ROOT) fail(`${label} has an unexpected content root`);
  if (typeof descriptor.head !== "string" || !/^(?:[a-f0-9]{40,64}|UNBORN)$/.test(descriptor.head)) fail(`${label} has an invalid Git head`);
  if (!Number.isSafeInteger(descriptor.entryCount) || descriptor.entryCount < 1) fail(`${label} has an invalid entryCount`);
  return descriptor;
}

export function createSourceSnapshotArtifact(repoRoot, snapshot, outputDirectory) {
  const root = realpathSync(repoRoot);
  if (!snapshot?.dirty) fail("recoverable source snapshots are required only for dirty reviewed source");
  const entries = validateSourceEntries(snapshot.entries);
  if (entries.length !== snapshot.entryCount || fingerprintRecords(entries) !== snapshot.fingerprint) {
    fail("source snapshot entries do not correspond to the attested fingerprint");
  }
  const metadata = {
    schemaVersion: SOURCE_SNAPSHOT_SCHEMA_VERSION,
    kind: SOURCE_SNAPSHOT_KIND,
    format: "ustar",
    fingerprintAlgorithm: "sha256",
    fingerprint: snapshot.fingerprint,
    head: snapshot.head,
    dirty: true,
    entryCount: entries.length,
    contentRoot: SOURCE_SNAPSHOT_CONTENT_ROOT,
    entries,
  };
  const metadataContent = canonicalJson(metadata);
  const filename = sourceSnapshotFilename(snapshot.fingerprint);
  mkdirSync(outputDirectory, { recursive: true });
  const temporaryDirectory = mkdtempSync(path.join(outputDirectory, ".janjacord-source-snapshot-"));
  const temporaryArchive = path.join(temporaryDirectory, filename);
  const archivePath = path.join(outputDirectory, filename);
  const digestPath = `${archivePath}.sha256`;
  let archivePublished = false;
  try {
    const descriptor = openSync(temporaryArchive, "wx", 0o600);
    try {
      const archiveEntries = [
        { path: SOURCE_SNAPSHOT_METADATA_FILENAME, type: "file", mode: 0o644, size: metadataContent.length, content: metadataContent },
        ...archiveDirectoryEntries(entries),
        ...entries.filter((record) => record.type !== "missing").map((record) => ({
          path: `${SOURCE_SNAPSHOT_CONTENT_ROOT}/${record.path}`,
          type: record.type,
          mode: record.type === "file" && record.executable ? 0o755 : record.type === "file" ? 0o644 : 0o777,
          size: record.type === "file" ? Number(record.size) : 0,
          targetBase64: record.targetBase64,
          record,
        })),
      ].sort((left, right) => comparePaths(left.path, right.path));
      for (const entry of archiveEntries) {
        writeAll(descriptor, createTarHeader(entry));
        if (entry.content) {
          writeAll(descriptor, entry.content);
          const padding = (tarBlockSize - (entry.content.length % tarBlockSize)) % tarBlockSize;
          if (padding) writeAll(descriptor, Buffer.alloc(padding));
        } else if (entry.record?.type === "file") {
          writeSourceFilePayload(descriptor, root, entry.record);
        } else if (entry.record?.type === "symlink") {
          assertSourceRecordStillMatches(root, entry.record);
        }
      }
      writeAll(descriptor, Buffer.alloc(tarBlockSize * 2));
    } finally {
      closeSync(descriptor);
    }
    const archiveSha256 = hashFileStable(temporaryArchive, lstatSync(temporaryArchive, { bigint: true }));
    const temporaryDigest = path.join(temporaryDirectory, `${filename}.sha256`);
    writeFileSync(temporaryDigest, `${archiveSha256}  ${filename}\n`, { encoding: "utf8", mode: 0o444, flag: "wx" });
    linkSync(temporaryArchive, archivePath);
    archivePublished = true;
    try {
      linkSync(temporaryDigest, digestPath);
    } catch (error) {
      unlinkSync(archivePath);
      archivePublished = false;
      throw error;
    }
    chmodSync(archivePath, 0o444);
    chmodSync(digestPath, 0o444);
    return {
      descriptor: validateSourceSnapshotDescriptor({
        format: "ustar",
        filename,
        digestFilename: `${filename}.sha256`,
        sha256: archiveSha256,
        metadataFilename: SOURCE_SNAPSHOT_METADATA_FILENAME,
        contentRoot: SOURCE_SNAPSHOT_CONTENT_ROOT,
        fingerprint: snapshot.fingerprint,
        head: snapshot.head,
        entryCount: entries.length,
      }),
      archivePath,
      digestPath,
    };
  } catch (error) {
    if (archivePublished && existsSync(archivePath)) unlinkSync(archivePath);
    throw error;
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function readExact(descriptor, length, position, label) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const bytesRead = readSync(descriptor, buffer, offset, length - offset, position + offset);
    if (bytesRead === 0) fail(`${label} ended unexpectedly`);
    offset += bytesRead;
  }
  return buffer;
}

function decodeTarString(buffer, label) {
  const end = buffer.indexOf(0);
  const bytes = end < 0 ? buffer : buffer.subarray(0, end);
  let decoded;
  try {
    decoded = utf8Decoder.decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  if (!Buffer.from(decoded, "utf8").equals(bytes)) fail(`${label} did not round-trip as UTF-8`);
  return decoded;
}

function parseTarOctal(buffer, label) {
  const value = buffer.toString("ascii").replace(/[\0 ]+$/g, "");
  if (!/^[0-7]+$/.test(value)) fail(`${label} is not canonical octal`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) fail(`${label} exceeds the safe integer range`);
  return parsed;
}

function readTarArchive(archivePath) {
  const archiveSize = statSync(archivePath).size;
  if (archiveSize < tarBlockSize * 2 || archiveSize % tarBlockSize !== 0) fail("source snapshot archive has an invalid USTAR size");
  const descriptor = openSync(archivePath, "r");
  const entries = new Map();
  let position = 0;
  let zeroBlocks = 0;
  try {
    while (position < archiveSize) {
      const header = readExact(descriptor, tarBlockSize, position, "source snapshot archive");
      position += tarBlockSize;
      if (header.every((byte) => byte === 0)) {
        zeroBlocks += 1;
        continue;
      }
      if (zeroBlocks > 0) fail("source snapshot archive contains content after its end marker");
      const storedChecksum = parseTarOctal(header.subarray(148, 156), "USTAR checksum");
      const checksumHeader = Buffer.from(header);
      checksumHeader.fill(0x20, 148, 156);
      const actualChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
      if (storedChecksum !== actualChecksum) fail("source snapshot archive has an invalid USTAR header checksum");
      if (header.subarray(257, 263).toString("binary") !== "ustar\0" || header.subarray(263, 265).toString("ascii") !== "00") {
        fail("source snapshot archive is not canonical USTAR");
      }
      const name = decodeTarString(header.subarray(0, 100), "USTAR name");
      const prefix = decodeTarString(header.subarray(345, 500), "USTAR prefix");
      const entryPath = prefix ? `${prefix}/${name}` : name;
      assertPortableRelativePath(entryPath, "USTAR entry path");
      if (entries.has(entryPath)) fail(`source snapshot archive contains duplicate entry ${entryPath}`);
      const size = parseTarOctal(header.subarray(124, 136), `USTAR size for ${entryPath}`);
      const mode = parseTarOctal(header.subarray(100, 108), `USTAR mode for ${entryPath}`) & 0o777;
      const typeFlag = String.fromCharCode(header[156]);
      const type = typeFlag === "0" ? "file" : typeFlag === "2" ? "symlink" : typeFlag === "5" ? "directory" : null;
      if (!type) fail(`source snapshot archive has unsupported USTAR type ${JSON.stringify(typeFlag)} for ${entryPath}`);
      if (type !== "file" && size !== 0) fail(`source snapshot ${type} ${entryPath} has non-zero content`);
      const entry = { path: entryPath, type, mode, size };
      if (type === "symlink") {
        const targetField = header.subarray(157, 257);
        const targetEnd = targetField.indexOf(0);
        entry.targetBase64 = Buffer.from(targetField.subarray(0, targetEnd < 0 ? targetField.length : targetEnd)).toString("base64");
      }
      if (type === "file") {
        const hash = createHash("sha256");
        let remaining = size;
        let contentPosition = position;
        let metadataContent = entryPath === SOURCE_SNAPSHOT_METADATA_FILENAME ? Buffer.alloc(size) : null;
        let metadataOffset = 0;
        let scanCarry = Buffer.alloc(0);
        while (remaining > 0) {
          const chunkLength = Math.min(1024 * 1024, remaining);
          const chunk = readExact(descriptor, chunkLength, contentPosition, `source snapshot entry ${entryPath}`);
          hash.update(chunk);
          if (entryPath.startsWith(`${SOURCE_SNAPSHOT_CONTENT_ROOT}/`)) {
            const scan = Buffer.concat([scanCarry, chunk]);
            assertContentHasNoPrivateKey(scan, entryPath);
            scanCarry = Buffer.from(scan.subarray(Math.max(0, scan.length - 128)));
          }
          if (metadataContent) {
            chunk.copy(metadataContent, metadataOffset);
            metadataOffset += chunk.length;
          }
          contentPosition += chunkLength;
          remaining -= chunkLength;
        }
        entry.sha256 = hash.digest("hex");
        if (metadataContent) entry.content = metadataContent;
      }
      entries.set(entryPath, entry);
      position += Math.ceil(size / tarBlockSize) * tarBlockSize;
      if (position > archiveSize) fail(`source snapshot entry ${entryPath} exceeds the archive`);
    }
  } finally {
    closeSync(descriptor);
  }
  if (zeroBlocks !== 2) fail("source snapshot archive must end with exactly two zero blocks");
  return entries;
}

function validateSourceSnapshotMetadata(metadata, label = "source snapshot metadata") {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) fail(`${label} is not an object`);
  if (Object.keys(metadata).sort().join(",") !== "contentRoot,dirty,entries,entryCount,fingerprint,fingerprintAlgorithm,format,head,kind,schemaVersion") {
    fail(`${label} has unexpected or missing fields`);
  }
  if (metadata.schemaVersion !== SOURCE_SNAPSHOT_SCHEMA_VERSION) fail(`${label} has unsupported schemaVersion`);
  if (metadata.kind !== SOURCE_SNAPSHOT_KIND) fail(`${label} has invalid kind`);
  if (metadata.format !== "ustar") fail(`${label} has unsupported format`);
  if (metadata.fingerprintAlgorithm !== "sha256") fail(`${label} has unsupported fingerprint algorithm`);
  if (!/^[a-f0-9]{64}$/.test(metadata.fingerprint)) fail(`${label} has an invalid fingerprint`);
  if (typeof metadata.head !== "string" || !/^(?:[a-f0-9]{40,64}|UNBORN)$/.test(metadata.head)) fail(`${label} has an invalid Git head`);
  if (metadata.dirty !== true) fail(`${label} must describe an explicitly reviewed dirty snapshot`);
  if (metadata.contentRoot !== SOURCE_SNAPSHOT_CONTENT_ROOT) fail(`${label} has an unexpected content root`);
  const entries = validateSourceEntries(metadata.entries, `${label} entries`);
  if (metadata.entryCount !== entries.length) fail(`${label} entryCount does not match its entries`);
  if (fingerprintRecords(entries) !== metadata.fingerprint) fail(`${label} entries do not correspond to its fingerprint`);
  return metadata;
}

function expectedTarEntries(metadata) {
  const expected = new Map();
  expected.set(SOURCE_SNAPSHOT_METADATA_FILENAME, { type: "file", mode: 0o644, size: canonicalJson(metadata).length });
  for (const directory of archiveDirectoryEntries(metadata.entries)) expected.set(directory.path, directory);
  for (const record of metadata.entries) {
    if (record.type === "missing") continue;
    expected.set(`${SOURCE_SNAPSHOT_CONTENT_ROOT}/${record.path}`, {
      type: record.type,
      mode: record.type === "file" && record.executable ? 0o755 : record.type === "file" ? 0o644 : 0o777,
      size: record.type === "file" ? Number(record.size) : 0,
      sha256: record.sha256,
      targetBase64: record.targetBase64,
    });
  }
  return expected;
}

export function validateSourceSnapshotArtifact(archivePath, expectedDescriptor) {
  if (!existsSync(archivePath) || !lstatSync(archivePath).isFile()) fail(`source snapshot archive is missing: ${archivePath}`);
  const filename = path.basename(archivePath);
  const filenameMatch = /^JanjaCord-source-([a-f0-9]{64})\.tar$/.exec(filename);
  if (!filenameMatch) fail(`source snapshot archive has a non-deterministic filename: ${filename}`);
  const archiveSha256 = hashFileStable(archivePath, lstatSync(archivePath, { bigint: true }));
  const digestPath = `${archivePath}.sha256`;
  if (!existsSync(digestPath) || !lstatSync(digestPath).isFile()) fail(`source snapshot digest is missing: ${digestPath}`);
  const expectedDigestContent = `${archiveSha256}  ${filename}\n`;
  if (readFileSync(digestPath, "utf8") !== expectedDigestContent) fail("source snapshot SHA-256 sidecar does not match the archive");
  const tarEntries = readTarArchive(archivePath);
  const metadataEntry = tarEntries.get(SOURCE_SNAPSHOT_METADATA_FILENAME);
  if (!metadataEntry?.content) fail("source snapshot archive is missing canonical metadata");
  let metadata;
  try {
    metadata = JSON.parse(metadataEntry.content.toString("utf8"));
  } catch (error) {
    fail(`source snapshot metadata is not valid JSON: ${error.message}`);
  }
  validateSourceSnapshotMetadata(metadata);
  if (!metadataEntry.content.equals(canonicalJson(metadata))) fail("source snapshot metadata is not canonical JSON");
  if (metadata.fingerprint !== filenameMatch[1]) fail("source snapshot filename fingerprint does not match its metadata");
  const expectedEntries = expectedTarEntries(metadata);
  if (tarEntries.size !== expectedEntries.size) fail(`source snapshot archive entry count mismatch: expected ${expectedEntries.size}, got ${tarEntries.size}`);
  for (const [entryPath, expected] of expectedEntries) {
    const actual = tarEntries.get(entryPath);
    if (!actual) fail(`source snapshot archive is missing ${entryPath}`);
    for (const field of ["type", "mode", "size"]) {
      if (actual[field] !== expected[field]) fail(`source snapshot archive ${field} mismatch for ${entryPath}`);
    }
    if (expected.sha256 && actual.sha256 !== expected.sha256) fail(`source snapshot content SHA-256 mismatch for ${entryPath}`);
    if (expected.targetBase64 && actual.targetBase64 !== expected.targetBase64) fail(`source snapshot symlink target mismatch for ${entryPath}`);
  }
  const descriptor = validateSourceSnapshotDescriptor({
    format: "ustar",
    filename,
    digestFilename: `${filename}.sha256`,
    sha256: archiveSha256,
    metadataFilename: SOURCE_SNAPSHOT_METADATA_FILENAME,
    contentRoot: SOURCE_SNAPSHOT_CONTENT_ROOT,
    fingerprint: metadata.fingerprint,
    head: metadata.head,
    entryCount: metadata.entryCount,
  });
  if (expectedDescriptor && JSON.stringify(validateSourceSnapshotDescriptor(expectedDescriptor)) !== JSON.stringify(descriptor)) {
    fail("source snapshot archive does not match the provenance manifest descriptor");
  }
  return { descriptor, metadata, archivePath, digestPath };
}

export function createSourceManifest(snapshot, options) {
  if (options?.sourceFrozen !== true) fail("source manifest requires sourceFrozen=true");
  if (snapshot.dirty && options.reviewedDirtySnapshot !== true) {
    fail("dirty source manifest requires reviewedDirtySnapshot=true");
  }
  const runtimeBuild = validateRuntimeBuildAttestation(options?.runtimeBuild);
  const privilegedPayloads = validatePrivilegedPayloadAttestation(snapshot.privilegedPayloads);
  const sourceSnapshot = snapshot.dirty
    ? validateSourceSnapshotDescriptor(options?.sourceSnapshot, "dirty source snapshot descriptor")
    : null;
  if (sourceSnapshot && (
    sourceSnapshot.fingerprint !== snapshot.fingerprint
    || sourceSnapshot.head !== snapshot.head
    || sourceSnapshot.entryCount !== snapshot.entryCount
  )) {
    fail("dirty source snapshot descriptor does not match the attested source");
  }
  return {
    schemaVersion: SOURCE_MANIFEST_SCHEMA_VERSION,
    kind: SOURCE_MANIFEST_KIND,
    fingerprintAlgorithm: "sha256",
    fingerprint: snapshot.fingerprint,
    head: snapshot.head,
    dirty: snapshot.dirty,
    reviewedDirtySnapshot: snapshot.dirty,
    sourceFrozen: true,
    entryCount: snapshot.entryCount,
    privilegedPayloadHashAlgorithm: "sha256",
    privilegedPayloads,
    sourceSnapshot,
    runtimeBuild,
  };
}

export function validateSourceManifest(manifest, label = "source manifest") {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) fail(`${label} is not a JSON object`);
  if (manifest.schemaVersion !== SOURCE_MANIFEST_SCHEMA_VERSION) fail(`${label} has unsupported schemaVersion`);
  if (manifest.kind !== SOURCE_MANIFEST_KIND) fail(`${label} has invalid kind`);
  if (manifest.fingerprintAlgorithm !== "sha256") fail(`${label} has unsupported fingerprintAlgorithm`);
  if (!/^[a-f0-9]{64}$/.test(manifest.fingerprint)) fail(`${label} has invalid fingerprint`);
  if (typeof manifest.head !== "string" || !/^(?:[a-f0-9]{40,64}|UNBORN)$/.test(manifest.head)) fail(`${label} has invalid Git head`);
  if (typeof manifest.dirty !== "boolean") fail(`${label} has invalid dirty marker`);
  if (typeof manifest.reviewedDirtySnapshot !== "boolean") fail(`${label} has invalid reviewedDirtySnapshot marker`);
  if (manifest.dirty && manifest.reviewedDirtySnapshot !== true) fail(`${label} describes an unreviewed dirty snapshot`);
  if (!manifest.dirty && manifest.reviewedDirtySnapshot !== false) fail(`${label} has an inconsistent clean-source review marker`);
  if (manifest.sourceFrozen !== true) fail(`${label} was not produced from an explicitly frozen source`);
  if (!Number.isSafeInteger(manifest.entryCount) || manifest.entryCount < 1) fail(`${label} has invalid entryCount`);
  if (manifest.privilegedPayloadHashAlgorithm !== "sha256") fail(`${label} has an unsupported privileged payload hash algorithm`);
  validatePrivilegedPayloadAttestation(manifest.privilegedPayloads, `${label} privilegedPayloads`);
  if (manifest.dirty) {
    const sourceSnapshot = validateSourceSnapshotDescriptor(manifest.sourceSnapshot, `${label} sourceSnapshot`);
    if (sourceSnapshot.fingerprint !== manifest.fingerprint || sourceSnapshot.head !== manifest.head || sourceSnapshot.entryCount !== manifest.entryCount) {
      fail(`${label} sourceSnapshot does not correspond to its source attestation`);
    }
  } else if (manifest.sourceSnapshot !== null) {
    fail(`${label} clean source must not claim a recoverable dirty snapshot`);
  }
  validateRuntimeBuildAttestation(manifest.runtimeBuild, `${label} runtimeBuild`);
  return manifest;
}

function selfTestRuntimeBuild() {
  const workspaces = [
    { name: "@janjacord/desktop", packagePath: "apps/desktop", outputRoots: ["dist"] },
    { name: "@janjacord/janjanode", packagePath: "apps/janjanode", outputRoots: ["dist"] },
  ];
  const payloads = [
    {
      workspace: "@janjacord/desktop",
      sourcePath: "apps/desktop/dist/index.html",
      asarPath: "dist/index.html",
      size: 1,
      sha256: "a".repeat(64),
    },
    {
      workspace: "@janjacord/janjanode",
      sourcePath: "apps/janjanode/dist/main.js",
      asarPath: "node_modules/@janjacord/janjanode/dist/main.js",
      size: 1,
      sha256: "b".repeat(64),
    },
  ].sort((left, right) => comparePaths(left.asarPath, right.asarPath));
  return validateRuntimeBuildAttestation({
    command: [...RUNTIME_BUILD_COMMAND],
    rootWorkspace: RUNTIME_BUILD_ROOT_WORKSPACE,
    payloadHashAlgorithm: "sha256",
    workspaces,
    payloads,
  }, "self-test runtime build");
}

function selfTestGit(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.error || result.status !== 0) fail(`self-test git ${args.join(" ")} failed: ${(result.stderr || result.error?.message || "").trim()}`);
}

export function runSourceFingerprintSelfTest() {
  const root = mkdtempSync(path.join(os.tmpdir(), "janjacord-source-fingerprint-"));
  const artifactRoot = mkdtempSync(path.join(os.tmpdir(), "janjacord-source-artifact-"));
  try {
    selfTestGit(root, ["init", "--quiet"]);
    selfTestGit(root, ["config", "user.name", "JanjaCord self-test"]);
    selfTestGit(root, ["config", "user.email", "self-test@invalid.local"]);
    mkdirSync(path.join(root, "apps/desktop/electron"), { recursive: true });
    mkdirSync(path.join(root, "apps/desktop/build"), { recursive: true });
    writeFileSync(path.join(root, "apps/desktop/electron/main.mjs"), "console.log('main fixture');\n", "utf8");
    writeFileSync(path.join(root, "apps/desktop/electron/preload.cjs"), "module.exports = 'preload fixture';\n", "utf8");
    writeFileSync(path.join(root, ".gitignore"), "dist/\n", "utf8");
    writeFileSync(path.join(root, "apps/desktop/tracked.txt"), "tracked-v1\n", "utf8");
    writeFileSync(path.join(root, "apps/desktop/build/icon.png"), "tracked-icon-fixture\n", "utf8");
    mkdirSync(path.join(root, "project-memory/.operational/artifacts"), { recursive: true });
    writeFileSync(path.join(root, "project-memory/.operational/artifacts/release-evidence.bin"), "excluded-evidence\n", "utf8");
    selfTestGit(root, ["add", ".gitignore", "apps/desktop/tracked.txt", "apps/desktop/build/icon.png", "apps/desktop/electron/main.mjs", "apps/desktop/electron/preload.cjs", "project-memory/.operational/artifacts/release-evidence.bin"]);
    selfTestGit(root, ["commit", "--quiet", "-m", "fixture"]);
    writeFileSync(path.join(root, "apps/desktop/tracked.txt"), "tracked-dirty\n", "utf8");
    writeFileSync(path.join(root, "apps/desktop/untracked.txt"), "untracked-v1\n", "utf8");
    writeFileSync(path.join(root, "apps/desktop/executable.sh"), "#!/bin/sh\nexit 0\n", "utf8");
    chmodSync(path.join(root, "apps/desktop/executable.sh"), 0o755);
    let symlinkCreated = true;
    try {
      symlinkSync("tracked.txt", path.join(root, "apps/desktop/tracked-link"));
    } catch (error) {
      if (process.platform !== "win32" || !["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) throw error;
      symlinkCreated = false;
    }
    writeFileSync(path.join(root, "local.db"), "outside-source-roots\n", "utf8");

    const initial = computeSourceSnapshot(root);
    const repeated = computeSourceSnapshot(root);
    assertSourceSnapshotUnchanged(initial, repeated, "determinism self-test");
    if (!initial.dirty) fail("self-test expected tracked modifications and untracked source to make the snapshot dirty");
    if (initial.entries.some((entry) => entry.path.startsWith("project-memory/.operational/artifacts/"))) {
      fail("release/evidence output was included in the source fingerprint");
    }
    const expectedSourcePaths = ["apps/desktop/tracked.txt", "apps/desktop/untracked.txt", "apps/desktop/executable.sh", "apps/desktop/build/icon.png"];
    if (symlinkCreated) expectedSourcePaths.push("apps/desktop/tracked-link");
    for (const expectedPath of expectedSourcePaths) {
      if (!initial.entries.some((entry) => entry.path === expectedPath)) fail(`source fingerprint omitted ${expectedPath}`);
    }
    if (initial.entries.some((entry) => entry.path === "local.db")) fail("source-root allowlist included a local database outside source roots");

    const artifact = createSourceSnapshotArtifact(root, initial, artifactRoot);
    const validatedArtifact = validateSourceSnapshotArtifact(artifact.archivePath, artifact.descriptor);
    if (validatedArtifact.metadata.fingerprint !== initial.fingerprint) fail("recoverable archive validation lost its source fingerprint");
    let immutableRejection;
    try {
      createSourceSnapshotArtifact(root, initial, artifactRoot);
    } catch (error) {
      immutableRejection = error;
    }
    if (!immutableRejection || !/exist|EEXIST/i.test(String(immutableRejection.message))) fail("source snapshot artifact could be overwritten");

    const reconstructedRoot = path.join(artifactRoot, "reconstructed");
    mkdirSync(reconstructedRoot);
    const extraction = spawnSync("tar", ["-xf", artifact.archivePath, "-C", reconstructedRoot], { encoding: "utf8" });
    if (extraction.error || extraction.status !== 0) fail(`source snapshot reconstruction failed: ${(extraction.stderr || extraction.error?.message || "").trim()}`);
    if (readFileSync(path.join(reconstructedRoot, SOURCE_SNAPSHOT_CONTENT_ROOT, "apps/desktop/tracked.txt"), "utf8") !== "tracked-dirty\n") {
      fail("source snapshot did not reconstruct the tracked modification");
    }
    if (readFileSync(path.join(reconstructedRoot, SOURCE_SNAPSHOT_CONTENT_ROOT, "apps/desktop/untracked.txt"), "utf8") !== "untracked-v1\n") {
      fail("source snapshot did not reconstruct untracked source");
    }
    if (process.platform !== "win32" && (statSync(path.join(reconstructedRoot, SOURCE_SNAPSHOT_CONTENT_ROOT, "apps/desktop/executable.sh")).mode & 0o111) === 0) {
      fail("source snapshot did not reconstruct executable mode");
    }
    if (symlinkCreated && readlinkSync(path.join(reconstructedRoot, SOURCE_SNAPSHOT_CONTENT_ROOT, "apps/desktop/tracked-link"), "utf8") !== "tracked.txt") {
      fail("source snapshot did not reconstruct a source symlink");
    }
    if (existsSync(path.join(reconstructedRoot, SOURCE_SNAPSHOT_CONTENT_ROOT, "project-memory/.operational/artifacts/release-evidence.bin"))) {
      fail("source snapshot reconstructed excluded release/evidence output");
    }

    mkdirSync(path.join(root, "dist"));
    writeFileSync(path.join(root, "dist/generated.txt"), "ignored-output\n", "utf8");
    assertSourceSnapshotUnchanged(initial, computeSourceSnapshot(root), "ignored-output self-test");

    writeFileSync(path.join(root, "apps/desktop/tracked.txt"), "tracked-v2\n", "utf8");
    const trackedChange = computeSourceSnapshot(root);
    if (trackedChange.fingerprint === initial.fingerprint) fail("tracked content did not affect the fingerprint");
    let mutationRejection;
    try {
      assertSourceSnapshotUnchanged(initial, trackedChange, "mutation self-test");
    } catch (error) {
      mutationRejection = error;
    }
    if (!mutationRejection?.message.includes("source changed during mutation self-test")) fail("source mutation was not rejected by the build-stability gate");
    validateSourceSnapshotArtifact(artifact.archivePath, artifact.descriptor);
    writeFileSync(path.join(root, "apps/desktop/tracked.txt"), "tracked-dirty\n", "utf8");

    writeFileSync(path.join(root, "apps/desktop/untracked.txt"), "untracked-v2\n", "utf8");
    if (computeSourceSnapshot(root).fingerprint === initial.fingerprint) fail("untracked content did not affect the fingerprint");
    writeFileSync(path.join(root, "apps/desktop/untracked.txt"), "untracked-v1\n", "utf8");

    unlinkSync(path.join(root, "apps/desktop/tracked.txt"));
    if (computeSourceSnapshot(root).fingerprint === initial.fingerprint) fail("tracked deletion did not affect the fingerprint");
    writeFileSync(path.join(root, "apps/desktop/tracked.txt"), "tracked-dirty\n", "utf8");

    writeFileSync(path.join(root, "apps/desktop/private.pem"), "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n", "utf8");
    let secretRejection;
    try {
      computeSourceSnapshot(root);
    } catch (error) {
      secretRejection = error;
    }
    if (!secretRejection?.message.includes("potential secret file")) fail("source fingerprint accepted a potential secret file");
    unlinkSync(path.join(root, "apps/desktop/private.pem"));
    writeFileSync(path.join(root, "apps/desktop/leaked-material.txt"), `-----BEGIN PRIVATE KEY-----\n${"A".repeat(64)}\n`, "utf8");
    let privateKeyRejection;
    try {
      computeSourceSnapshot(root);
    } catch (error) {
      privateKeyRejection = error;
    }
    if (!privateKeyRejection?.message.includes("private-key material")) fail("source fingerprint accepted private-key content under an ordinary filename");
    unlinkSync(path.join(root, "apps/desktop/leaked-material.txt"));

    for (const sensitivePath of [
      "apps/desktop/local.db",
      "apps/desktop/cache.db3",
      "apps/desktop/local.db-wal",
      "apps/desktop/vault.json",
      "apps/desktop/community.vault",
      "apps/desktop/backup.tar",
      "apps/desktop/session.token",
      "apps/desktop/client.secret",
      "apps/desktop/credentials.json",
      "apps/desktop/backups/archive.bin",
    ]) {
      const absoluteSensitivePath = path.join(root, ...sensitivePath.split("/"));
      mkdirSync(path.dirname(absoluteSensitivePath), { recursive: true });
      writeFileSync(absoluteSensitivePath, "sensitive-fixture\n", "utf8");
      let artifactRejection;
      try {
        computeSourceSnapshot(root);
      } catch (error) {
        artifactRejection = error;
      }
      if (!artifactRejection?.message.includes("potential secret file")) {
        fail(`source fingerprint accepted sensitive local artifact ${sensitivePath}`);
      }
      unlinkSync(absoluteSensitivePath);
    }
    rmSync(path.join(root, "apps/desktop/backups"), { recursive: true, force: true });

    const originalDigest = readFileSync(artifact.digestPath, "utf8");
    chmodSync(artifact.digestPath, 0o644);
    writeFileSync(artifact.digestPath, `${"0".repeat(64)}  ${path.basename(artifact.archivePath)}\n`, "utf8");
    let digestTamperRejection;
    try {
      validateSourceSnapshotArtifact(artifact.archivePath, artifact.descriptor);
    } catch (error) {
      digestTamperRejection = error;
    }
    if (!digestTamperRejection?.message.includes("sidecar does not match")) fail("source snapshot accepted a tampered digest sidecar");
    writeFileSync(artifact.digestPath, originalDigest, "utf8");
    chmodSync(artifact.digestPath, 0o444);

    const tamperRoot = path.join(artifactRoot, "tamper");
    mkdirSync(tamperRoot);
    const tamperedArchive = path.join(tamperRoot, path.basename(artifact.archivePath));
    const tamperedBytes = readFileSync(artifact.archivePath);
    const contentOffset = tamperedBytes.indexOf(Buffer.from("tracked-dirty\n"));
    if (contentOffset < 0) fail("self-test could not locate source payload in the USTAR archive");
    tamperedBytes[contentOffset] ^= 0xff;
    writeFileSync(tamperedArchive, tamperedBytes);
    const tamperedSha256 = createHash("sha256").update(tamperedBytes).digest("hex");
    writeFileSync(`${tamperedArchive}.sha256`, `${tamperedSha256}  ${path.basename(tamperedArchive)}\n`, "utf8");
    let contentTamperRejection;
    try {
      validateSourceSnapshotArtifact(tamperedArchive);
    } catch (error) {
      contentTamperRejection = error;
    }
    if (!contentTamperRejection?.message.includes("content SHA-256 mismatch")) {
      fail("source snapshot accepted coordinated archive and digest tampering");
    }

    const runtimeBuild = selfTestRuntimeBuild();
    const manifest = createSourceManifest(initial, {
      sourceFrozen: true,
      reviewedDirtySnapshot: true,
      runtimeBuild,
      sourceSnapshot: artifact.descriptor,
    });
    validateSourceManifest(manifest, "self-test manifest");
    let rejectedUnreviewed = false;
    try {
      createSourceManifest(initial, { sourceFrozen: true, reviewedDirtySnapshot: false, runtimeBuild });
    } catch {
      rejectedUnreviewed = true;
    }
    if (!rejectedUnreviewed) fail("dirty manifest was accepted without explicit review");
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(artifactRoot, { recursive: true, force: true });
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runSourceFingerprintSelfTest();
  console.log("source fingerprint self-test passed");
}
