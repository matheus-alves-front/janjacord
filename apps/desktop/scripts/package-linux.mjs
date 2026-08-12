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

function assertPackagingAuthorization(env, snapshot) {
  if (env.JANJACORD_SOURCE_FROZEN !== "1") {
    fail("Linux packaging refused: set JANJACORD_SOURCE_FROZEN=1 only after freezing the exact reviewed source snapshot for the duration of the build.");
  }
  if (snapshot.dirty && env.JANJACORD_REVIEWED_DIRTY_SNAPSHOT !== "1") {
    fail("Linux packaging refused: this worktree is dirty. After reviewing every tracked and untracked non-ignored source file, set JANJACORD_REVIEWED_DIRTY_SNAPSHOT=1 together with JANJACORD_SOURCE_FROZEN=1.");
  }
}

function prepareAtomicReleaseTarget() {
  if (!existsSync(releaseDir)) return;
  const releaseStat = lstatSync(releaseDir);
  if (!releaseStat.isDirectory() || releaseStat.isSymbolicLink()) {
    fail("Linux packaging refused: apps/desktop/release must be an ordinary directory or absent.");
  }
  const existingOutputs = readdirSync(releaseDir);
  if (existingOutputs.length > 0) {
    fail(`Linux packaging refused: move every existing output out of apps/desktop/release first: ${existingOutputs.join(", ")}`);
  }
  rmSync(releaseDir, { recursive: true });
}

function assertManifestOutputIsIgnored() {
  const relativeManifest = path.relative(workspaceRoot, manifestPath);
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", relativeManifest], { cwd: workspaceRoot });
  if (result.error) fail(`Linux packaging refused: unable to verify that ${relativeManifest} is ignored: ${result.error.message}`);
  if (result.status !== 0) {
    fail(`Linux packaging refused: ${relativeManifest} must remain ignored so provenance output cannot alter the source snapshot.`);
  }
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
  if (existsSync(releaseDir)) fail("Linux packaging refused to replace an existing release directory during atomic publish.");
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

function createBuilderEnvironment(env) {
  const compatibilityDirectory = env.JANJACORD_LIBCRYPT_COMPAT_DIR;
  return compatibilityDirectory
    ? {
        ...env,
        LD_LIBRARY_PATH: [path.resolve(compatibilityDirectory), env.LD_LIBRARY_PATH].filter(Boolean).join(path.delimiter),
      }
    : env;
}

function runSelfTest() {
  runSourceFingerprintSelfTest();
  const clean = { dirty: false };
  const dirty = { dirty: true };
  assertPackagingAuthorization({ JANJACORD_SOURCE_FROZEN: "1" }, clean);
  assertPackagingAuthorization({ JANJACORD_SOURCE_FROZEN: "1", JANJACORD_REVIEWED_DIRTY_SNAPSHOT: "1", CI: "false" }, dirty);

  for (const [label, env, snapshot] of [
    ["missing frozen marker", {}, clean],
    ["dirty review without frozen source", { JANJACORD_REVIEWED_DIRTY_SNAPSHOT: "1" }, dirty],
    ["unreviewed dirty snapshot", { JANJACORD_SOURCE_FROZEN: "1", CI: "true" }, dirty],
  ]) {
    let rejection;
    try {
      assertPackagingAuthorization(env, snapshot);
    } catch (error) {
      rejection = error;
    }
    if (!rejection?.message.includes("Linux packaging refused")) fail(`self-test did not reject ${label} with the expected authorization error`);
  }
  const unchangedEnvironment = { SENTINEL: "preserved" };
  if (createBuilderEnvironment(unchangedEnvironment) !== unchangedEnvironment) fail("self-test changed the builder environment without a compatibility directory");
  const compatibilityEnvironment = createBuilderEnvironment({
    JANJACORD_LIBCRYPT_COMPAT_DIR: "relative-libcrypt-compat",
    LD_LIBRARY_PATH: "/existing-library-path",
    SENTINEL: "preserved",
  });
  const expectedLibraryPath = [path.resolve("relative-libcrypt-compat"), "/existing-library-path"].join(path.delimiter);
  if (compatibilityEnvironment.LD_LIBRARY_PATH !== expectedLibraryPath || compatibilityEnvironment.SENTINEL !== "preserved") {
    fail("self-test did not preserve JANJACORD_LIBCRYPT_COMPAT_DIR propagation into LD_LIBRARY_PATH");
  }
  console.log("Linux packaging provenance self-test passed");
}

function main() {
  if (args.includes("--self-test")) {
    if (args.length !== 1) fail("--self-test cannot be combined with other arguments");
    runSelfTest();
    return;
  }
  if (args.length > 0) fail(`unsupported argument(s): ${args.join(" ")}`);

  if (process.env.JANJACORD_SOURCE_FROZEN !== "1") {
    fail("Linux packaging refused: set JANJACORD_SOURCE_FROZEN=1 only after freezing the exact reviewed source snapshot for the duration of the build.");
  }
  prepareAtomicReleaseTarget();
  assertManifestOutputIsIgnored();
  run(process.execPath, [path.join(scriptDir, "validate-desktop-artifacts.mjs"), "--platform", "config"], { cwd: appDir });
  run(process.execPath, [path.join(scriptDir, "check-linux-packaging-host.mjs")], { cwd: appDir });

  const source = computeSourceSnapshot(workspaceRoot);
  assertPackagingAuthorization(process.env, source);
  if (source.dirty) {
    console.warn("Packaging an explicitly reviewed dirty worktree snapshot. This attestation is provenance metadata; it does not claim CI execution, signing, or release approval.");
  }

  const releaseStagingDirectory = mkdtempSync(path.join(appDir, ".release-staging-linux-"));
  const sourceSnapshotStagingDirectory = mkdtempSync(path.join(appDir, ".source-snapshot-staging-linux-"));
  let published = false;
  let runtimePlan;
  try {
    const sourceArtifact = source.dirty ? createSourceSnapshotArtifact(workspaceRoot, source, sourceSnapshotStagingDirectory) : null;
    if (sourceArtifact) validateSourceSnapshotArtifact(sourceArtifact.archivePath, sourceArtifact.descriptor);

    runtimePlan = discoverRuntimeWorkspacePlan(workspaceRoot);
    cleanGeneratedRuntimeOutputs(workspaceRoot, runtimePlan);
    run(RUNTIME_BUILD_COMMAND[0], RUNTIME_BUILD_COMMAND.slice(1), { cwd: workspaceRoot });
    assertSourceSnapshotUnchanged(source, computeSourceSnapshot(workspaceRoot), "runtime workspace build");
    const runtimeBuild = computeRuntimeBuildAttestation(workspaceRoot, runtimePlan);
    writeSourceManifest(source, runtimeBuild, sourceArtifact?.descriptor ?? null);

    const builderEnvironment = createBuilderEnvironment(process.env);
    run("pnpm", ["exec", "electron-builder", "--linux", "AppImage", "deb", "--publish", "never", `--config.directories.output=${releaseStagingDirectory}`], {
      cwd: appDir,
      env: builderEnvironment,
    });
    assertSourceSnapshotUnchanged(source, computeSourceSnapshot(workspaceRoot), "electron-builder packaging");
    copySourceSnapshotToReleaseStaging(sourceArtifact, releaseStagingDirectory);
    run(process.execPath, [path.join(scriptDir, "validate-desktop-artifacts.mjs"), "--platform", "linux", "--release-dir", releaseStagingDirectory], { cwd: appDir });
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
