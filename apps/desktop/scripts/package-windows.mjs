#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { constants, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  SOURCE_MANIFEST_FILENAME,
  RUNTIME_BUILD_COMMAND,
  assertSourceSnapshotUnchanged,
  cleanGeneratedRuntimeOutputs,
  computeRuntimeBuildAttestation,
  computeSourceSnapshot,
  createSourceSnapshotArtifact,
  createSourceManifest,
  discoverRuntimeWorkspacePlan,
  runSourceFingerprintSelfTest,
  validateSourceSnapshotArtifact,
} from "./source-fingerprint.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, "..");
const workspaceRoot = path.resolve(appDir, "../..");
const releaseDir = path.join(appDir, "release");
const manifestPath = path.join(appDir, "dist", SOURCE_MANIFEST_FILENAME);
const args = process.argv.slice(2);

function fail(message) {
  throw new Error(message);
}

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd ?? workspaceRoot,
    stdio: "inherit",
    env: options.env ?? process.env,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const error = new Error(`${command} ${commandArgs.join(" ")} failed with exit code ${result.status ?? 1}`);
    error.exitCode = result.status ?? 1;
    throw error;
  }
}

function packagingMode(argv) {
  if (argv.length !== 1 || !["--unsigned-test", "--signed-release"].includes(argv[0])) {
    fail("Windows packaging requires exactly one mode: --unsigned-test or --signed-release.");
  }
  return argv[0] === "--unsigned-test" ? "unsigned" : "signed";
}

function assertPackagingAuthorization(env, snapshot, mode) {
  if (env.JANJACORD_SOURCE_FROZEN !== "1") {
    fail("Windows packaging refused: set JANJACORD_SOURCE_FROZEN=1 only after freezing the exact reviewed source snapshot for the duration of the build.");
  }
  if (snapshot.dirty && env.JANJACORD_REVIEWED_DIRTY_SNAPSHOT !== "1") {
    fail("Windows packaging refused: this worktree is dirty. After reviewing every tracked and untracked source input, set JANJACORD_REVIEWED_DIRTY_SNAPSHOT=1 with JANJACORD_SOURCE_FROZEN=1.");
  }
  if (mode === "unsigned" && ["CSC_LINK", "WIN_CSC_LINK", "CSC_KEY_PASSWORD", "WIN_CSC_KEY_PASSWORD"].some((name) => env[name])) {
    fail("Unsigned Windows test packaging refused because signing credentials are present in the environment.");
  }
}

function prepareAtomicReleaseTarget() {
  if (!existsSync(releaseDir)) return;
  const releaseStat = lstatSync(releaseDir);
  if (!releaseStat.isDirectory() || releaseStat.isSymbolicLink()) {
    fail("Windows packaging refused: apps/desktop/release must be an ordinary directory or absent.");
  }
  const existingOutputs = readdirSync(releaseDir);
  if (existingOutputs.length > 0) {
    fail(`Windows packaging refused: move every existing output out of apps/desktop/release first: ${existingOutputs.join(", ")}`);
  }
  rmSync(releaseDir, { recursive: true });
}

function assertManifestOutputIsIgnored() {
  const relativeManifest = path.relative(workspaceRoot, manifestPath);
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", relativeManifest], { cwd: workspaceRoot });
  if (result.error) fail(`Windows packaging refused: unable to verify that ${relativeManifest} is ignored: ${result.error.message}`);
  if (result.status !== 0) fail(`Windows packaging refused: ${relativeManifest} must remain ignored so provenance output cannot alter the source snapshot.`);
}

function writeSourceManifest(snapshot, runtimeBuild, sourceSnapshot) {
  const manifest = createSourceManifest(snapshot, {
    sourceFrozen: true,
    reviewedDirtySnapshot: process.env.JANJACORD_REVIEWED_DIRTY_SNAPSHOT === "1",
    runtimeBuild,
    sourceSnapshot,
  });
  mkdirSync(path.dirname(manifestPath), { recursive: true });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

function publishReleaseAtomically(stagingDirectory) {
  if (existsSync(releaseDir)) fail("Windows packaging refused to replace an existing release directory during atomic publish.");
  renameSync(stagingDirectory, releaseDir);
}

function copySourceSnapshotToReleaseStaging(sourceArtifact, stagingDirectory) {
  if (!sourceArtifact) return;
  const archivePath = path.join(stagingDirectory, sourceArtifact.descriptor.filename);
  const digestPath = path.join(stagingDirectory, sourceArtifact.descriptor.digestFilename);
  copyFileSync(sourceArtifact.archivePath, archivePath, constants.COPYFILE_EXCL);
  copyFileSync(sourceArtifact.digestPath, digestPath, constants.COPYFILE_EXCL);
  validateSourceSnapshotArtifact(archivePath, sourceArtifact.descriptor);
}

function runSelfTest() {
  runSourceFingerprintSelfTest();
  const clean = { dirty: false };
  const dirty = { dirty: true };
  assertPackagingAuthorization({ JANJACORD_SOURCE_FROZEN: "1" }, clean, "unsigned");
  assertPackagingAuthorization({ JANJACORD_SOURCE_FROZEN: "1", JANJACORD_REVIEWED_DIRTY_SNAPSHOT: "1" }, dirty, "signed");
  for (const [label, env, snapshot, mode] of [
    ["missing frozen marker", {}, clean, "unsigned"],
    ["dirty review without frozen source", { JANJACORD_REVIEWED_DIRTY_SNAPSHOT: "1" }, dirty, "signed"],
    ["unreviewed dirty snapshot", { JANJACORD_SOURCE_FROZEN: "1" }, dirty, "signed"],
    ["unsigned credentials", { JANJACORD_SOURCE_FROZEN: "1", CSC_LINK: "fixture" }, clean, "unsigned"],
  ]) {
    let rejection;
    try {
      assertPackagingAuthorization(env, snapshot, mode);
    } catch (error) {
      rejection = error;
    }
    if (!rejection?.message.includes("Windows packaging refused") && !rejection?.message.includes("Unsigned Windows test packaging refused")) {
      fail(`self-test did not reject ${label}`);
    }
  }
  console.log("Windows packaging provenance self-test passed");
}

function main() {
  if (args.includes("--self-test")) {
    if (args.length !== 1) fail("--self-test cannot be combined with other arguments");
    runSelfTest();
    return;
  }
  const mode = packagingMode(args);
  if (process.platform !== "win32") fail("Windows packaging must run on a real Windows host or runner.");

  prepareAtomicReleaseTarget();
  assertManifestOutputIsIgnored();
  run(process.execPath, [path.join(scriptDir, "validate-desktop-artifacts.mjs"), "--platform", "config"], { cwd: appDir });

  const source = computeSourceSnapshot(workspaceRoot);
  assertPackagingAuthorization(process.env, source, mode);
  if (source.dirty) {
    console.warn("Packaging an explicitly reviewed dirty Windows source snapshot. This provenance does not claim signing or release approval.");
  }

  const releaseStagingDirectory = mkdtempSync(path.join(appDir, `.release-staging-windows-${mode}-`));
  const sourceSnapshotStagingDirectory = mkdtempSync(path.join(appDir, `.source-snapshot-staging-windows-${mode}-`));
  let published = false;
  let runtimePlan;
  try {
    const sourceArtifact = source.dirty ? createSourceSnapshotArtifact(workspaceRoot, source, sourceSnapshotStagingDirectory) : null;
    if (sourceArtifact) validateSourceSnapshotArtifact(sourceArtifact.archivePath, sourceArtifact.descriptor);

    runtimePlan = discoverRuntimeWorkspacePlan(workspaceRoot);
    cleanGeneratedRuntimeOutputs(workspaceRoot, runtimePlan);
    run(RUNTIME_BUILD_COMMAND[0], RUNTIME_BUILD_COMMAND.slice(1), { cwd: workspaceRoot });
    assertSourceSnapshotUnchanged(source, computeSourceSnapshot(workspaceRoot), "Windows runtime workspace build");
    const runtimeBuild = computeRuntimeBuildAttestation(workspaceRoot, runtimePlan);
    writeSourceManifest(source, runtimeBuild, sourceArtifact?.descriptor ?? null);

    const builderArgs = ["exec", "electron-builder", "--win", "nsis", "--publish", "never", `--config.directories.output=${releaseStagingDirectory}`];
    if (mode === "signed") builderArgs.push("--config.forceCodeSigning=true");
    const builderEnvironment = mode === "unsigned"
      ? { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: "false" }
      : process.env;
    run("pnpm", builderArgs, { cwd: appDir, env: builderEnvironment });
    assertSourceSnapshotUnchanged(source, computeSourceSnapshot(workspaceRoot), "Windows electron-builder packaging");
    copySourceSnapshotToReleaseStaging(sourceArtifact, releaseStagingDirectory);
    run(process.execPath, [
      path.join(scriptDir, "validate-desktop-artifacts.mjs"),
      "--platform", "windows",
      "--release-dir", releaseStagingDirectory,
      "--windows-signature", mode === "unsigned" ? "unsigned" : "valid",
    ], { cwd: appDir });
    publishReleaseAtomically(releaseStagingDirectory);
    published = true;
  } finally {
    rmSync(sourceSnapshotStagingDirectory, { recursive: true, force: true });
    if (!published) {
      rmSync(releaseStagingDirectory, { recursive: true, force: true });
      if (runtimePlan) cleanGeneratedRuntimeOutputs(workspaceRoot, runtimePlan);
    }
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = Number.isInteger(error?.exitCode) ? error.exitCode : 2;
}
