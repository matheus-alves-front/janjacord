#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  RUNTIME_BUILD_COMMAND,
  RUNTIME_BUILD_ROOT_WORKSPACE,
  SOURCE_MANIFEST_FILENAME,
  computeRuntimeBuildAttestation,
  computeSourceSnapshot,
  createSourceManifest,
  discoverRuntimeWorkspacePlan,
  runSourceFingerprintSelfTest,
  validateSourceManifest,
  validateSourceSnapshotArtifact,
} from "./source-fingerprint.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, "..");
const workspaceRoot = path.resolve(appDir, "../..");
const packageJsonPath = path.join(appDir, "package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
const args = process.argv.slice(2);

function option(name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
}

function fail(message) {
  throw new Error(message);
}

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd ?? workspaceRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) fail(`${command} could not run: ${result.error.message}`);
  if (result.status !== 0) fail(`${command} ${commandArgs.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`);
  return result.stdout;
}

function walk(root, predicate) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const absolute = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute, predicate));
    else if (entry.isFile() && predicate(absolute)) files.push(absolute);
  }
  return files;
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function sha256Content(content) {
  return createHash("sha256").update(content).digest("hex");
}

function findAsarCli() {
  const pnpmStore = path.join(workspaceRoot, "node_modules/.pnpm");
  const asarClis = walk(pnpmStore, (file) => file.split(path.sep).join("/").endsWith("/node_modules/@electron/asar/bin/asar.js"));
  if (asarClis.length !== 1) fail(`expected exactly one installed @electron/asar CLI, found ${asarClis.length}`);
  return asarClis[0];
}

function validatePackageConfig() {
  const build = packageJson.build ?? {};
  if (build.asar !== true) fail("build.asar must be explicitly true");
  if (build.icon !== "build/icon.png") fail("build.icon must be build/icon.png");
  if (build.publish != null) fail("publish configuration must stay absent until a real update channel exists");
  const linuxTargets = new Set((build.linux?.target ?? []).map((target) => typeof target === "string" ? target.toLowerCase() : String(target.target).toLowerCase()));
  if (!linuxTargets.has("appimage") || !linuxTargets.has("deb")) fail("Linux targets must include AppImage and deb");
  for (const hook of ["afterInstall", "afterRemove", "after-install", "after-remove"]) {
    if (JSON.stringify(build).includes(hook)) fail(`global Linux lifecycle hook is forbidden: ${hook}`);
  }
  if (!packageJson.scripts?.["dist:win:release"]?.includes("package-windows.mjs --signed-release")) fail("Windows release command must use the guarded signed packaging wrapper");
  if (!packageJson.scripts?.["dist:win:test"]?.includes("package-windows.mjs --unsigned-test")) fail("Windows test command must use the guarded unsigned packaging wrapper");
  if (!packageJson.scripts?.["dist:linux"]?.includes("package-linux.mjs")) fail("Linux packaging must use the guarded packaging script");
  if (!packageJson.scripts?.dist?.includes("package-explicit.mjs")) fail("generic packaging must fail with platform/signing guidance");
  const cleanupResource = (build.extraResources ?? []).find((entry) => entry?.to === "janjacord-cleanup-autostart");
  if (cleanupResource?.from !== "scripts/janjacord-cleanup-autostart") fail("the per-user Linux autostart cleanup helper must be packaged as an extra resource");
}

function validatePackagingWrapperContracts() {
  const linuxWrapper = readFileSync(path.join(appDir, "scripts/package-linux.mjs"), "utf8");
  const windowsWrapper = readFileSync(path.join(appDir, "scripts/package-windows.mjs"), "utf8");
  for (const [label, wrapper] of [["Linux", linuxWrapper], ["Windows", windowsWrapper]]) {
    const configGate = wrapper.indexOf('"validate-desktop-artifacts.mjs"), "--platform", "config"');
    const runtimeBuild = wrapper.indexOf("run(RUNTIME_BUILD_COMMAND[0]");
    if (configGate < 0 || runtimeBuild < 0 || configGate > runtimeBuild) {
      fail(`${label} packaging must validate release configuration before the runtime build`);
    }
    for (const required of ["releaseStagingDirectory", "publishReleaseAtomically", "assertSourceSnapshotUnchanged", "createSourceManifest"]) {
      if (!wrapper.includes(required)) fail(`${label} packaging wrapper is missing ${required}`);
    }
  }
  for (const required of [
    "JANJACORD_SOURCE_FROZEN",
    "JANJACORD_REVIEWED_DIRTY_SNAPSHOT",
    "createSourceSnapshotArtifact",
    "--config.forceCodeSigning=true",
    "--windows-signature",
  ]) {
    if (!windowsWrapper.includes(required)) fail(`guarded Windows packaging wrapper is missing ${required}`);
  }

  const linuxWorkflow = readFileSync(path.join(workspaceRoot, ".github/workflows/linux-packaging-test.yml"), "utf8");
  const windowsWorkflow = readFileSync(path.join(workspaceRoot, ".github/workflows/windows-unsigned-test.yml"), "utf8");
  const linuxConfigGate = linuxWorkflow.indexOf("validate:release-config");
  const linuxPackageStep = linuxWorkflow.indexOf("run dist:linux");
  if (linuxConfigGate < 0 || linuxPackageStep < 0 || linuxConfigGate > linuxPackageStep) {
    fail("Linux workflow must validate release configuration before packaging");
  }
  for (const required of ["JANJACORD_SOURCE_FROZEN", "package-windows.mjs --self-test", "run dist:win:test"]) {
    if (!windowsWorkflow.includes(required)) fail(`Windows unsigned workflow is missing ${required}`);
  }
}

function validateAutostartContract() {
  const main = readFileSync(path.join(appDir, "electron/main.mjs"), "utf8");
  const start = main.indexOf('ipcMain.handle("hosting.autostart"');
  const end = main.indexOf('ipcMain.handle("hosting.candidate.register"', start);
  if (start < 0 || end < 0) fail("hosting.autostart handler not found");
  const handler = main.slice(start, end);
  if (!handler.includes("process.env.APPIMAGE")) fail("Linux AppImage autostart must use the persistent APPIMAGE path");
  if (!handler.includes("TryExec=")) fail("Linux autostart entry must fail safely with TryExec");
  if (!handler.includes("X-JanjaCord-Autostart=true")) fail("Linux autostart entry must carry the ownership marker used by safe cleanup");
}

function validateIcon() {
  const png = path.join(appDir, "build/icon.png");
  const svg = path.join(appDir, "build/icon.svg");
  if (!existsSync(png) || !existsSync(svg)) fail("PNG and SVG application icons are required");
  const data = readFileSync(png);
  if (data.length < 8 || data.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") fail("icon.png is not a PNG");
  if (data.length > 2 * 1024 * 1024) fail("icon.png unexpectedly exceeds 2 MiB");
  const width = data.readUInt32BE(16);
  const height = data.readUInt32BE(20);
  if (width !== 512 || height !== 512) fail(`icon.png must be 512x512, got ${width}x${height}`);
  const svgText = readFileSync(svg, "utf8");
  if (!/<svg[\s>]/.test(svgText) || !/viewBox=/.test(svgText)) fail("icon.svg is missing an SVG root or viewBox");
  for (const relativePath of ["apps/desktop/build/icon.png", "apps/desktop/build/icon.svg"]) {
    const tracked = spawnSync("git", ["ls-files", "--error-unmatch", "--", relativePath], { cwd: workspaceRoot, encoding: "utf8" });
    if (tracked.error || tracked.status !== 0) fail(`${relativePath} must be tracked by Git as a recoverable release source input`);
  }
  const source = computeSourceSnapshot(workspaceRoot);
  for (const relativePath of ["apps/desktop/build/icon.png", "apps/desktop/build/icon.svg"]) {
    if (!source.entries.some((entry) => entry.path === relativePath && entry.type === "file")) {
      fail(`${relativePath} is not included in the recoverable source snapshot`);
    }
  }
}

function validateRendererCsp() {
  const html = readFileSync(path.join(appDir, "index.html"), "utf8");
  const meta = /<meta\s+http-equiv=["']Content-Security-Policy["'][^>]+>/i.exec(html)?.[0] ?? "";
  const contentMatch = /\scontent="([^"]+)"/i.exec(meta) ?? /\scontent='([^']+)'/i.exec(meta);
  const csp = contentMatch?.[1];
  if (!csp) fail("renderer Content-Security-Policy meta tag is missing");
  const connectSource = /(?:^|;)\s*connect-src\s+([^;]+)/i.exec(csp)?.[1] ?? "";
  if (/(?:^|\s)wss:(?:\s|$)/i.test(connectSource)) fail("renderer CSP must not allow arbitrary wss: origins");
  for (const required of ["'self'", "ws://127.0.0.1:*", "ws://localhost:*"]) {
    if (!connectSource.split(/\s+/).includes(required)) fail(`renderer CSP connect-src is missing ${required}`);
  }
}

function validateNoGlobalHooks() {
  const scanRoots = [path.join(appDir, "package.json"), path.join(appDir, "build"), path.join(workspaceRoot, ".github/workflows")].filter(existsSync);
  const forbidden = /(?:ufw|firewall-cmd|firewalld|netsh\s+advfirewall|New-NetFirewallRule|Remove-NetFirewallRule|\/home\/\*|getent\s+passwd|\/etc\/passwd|\.config\/autostart.*(?:rm|unlink))/i;
  const files = [];
  for (const root of scanRoots) {
    if (statSync(root).isFile()) files.push(root);
    else files.push(...walk(root, () => true));
  }
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    if (forbidden.test(text)) fail(`forbidden firewall/global-user lifecycle pattern found in ${path.relative(workspaceRoot, file)}`);
  }
}

function requireAsarEntries(entries, label) {
  for (const required of ["/electron/main.mjs", "/electron/preload.cjs", "/dist/index.html", `/dist/${SOURCE_MANIFEST_FILENAME}`, "/package.json"]) {
    if (!entries.includes(required)) fail(`${label} app.asar is missing ${required}`);
  }
}

function validateAsar(asarPath, label, asarCli) {
  if (!existsSync(asarPath)) fail(`${label} is missing app.asar`);
  const size = statSync(asarPath).size;
  if (size < 1024 * 1024) fail(`${label} app.asar is implausibly small (${size} bytes)`);
  if (size > 160 * 1024 * 1024) fail(`${label} app.asar exceeds 160 MiB (${size} bytes)`);
  const entries = run(process.execPath, [asarCli, "list", asarPath]).split("\n");
  requireAsarEntries(entries, label);
  for (const forbidden of [/\/node_modules\/@janjacord\/[^/]+\/src\//, /\/node_modules\/@janjacord\/[^/]+\/scripts\//, /\.test\./, /\/node_modules\/@janjacord\/[^/]+\/target\//, /\.map$/]) {
    if (entries.some((entry) => forbidden.test(entry))) fail(`${label} app.asar contains excluded content matching ${forbidden}`);
  }
  return { path: asarPath, entries };
}

function extractAsar(asarPath, label, asarCli, tempRoot) {
  const extractionRoot = path.join(tempRoot, `${label.toLowerCase()}-asar`);
  run(process.execPath, [asarCli, "extract", asarPath, extractionRoot]);
  return extractionRoot;
}

function readExtractedSourceManifest(extractionRoot, label) {
  const extracted = path.join(extractionRoot, "dist", SOURCE_MANIFEST_FILENAME);
  if (!existsSync(extracted)) fail(`${label} app.asar source manifest could not be extracted`);
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(extracted, "utf8"));
  } catch (error) {
    fail(`${label} app.asar source manifest is not valid JSON: ${error.message}`);
  }
  return validateSourceManifest(parsed, `${label} app.asar source manifest`);
}

function requireAttestedPayloadEntries(entries, manifest, label) {
  for (const payload of manifest.runtimeBuild.payloads) {
    if (!entries.includes(`/${payload.asarPath}`)) fail(`${label} app.asar is missing attested runtime payload /${payload.asarPath}`);
  }
  for (const payload of manifest.privilegedPayloads) {
    if (!entries.includes(`/${payload.asarPath}`)) fail(`${label} app.asar is missing attested privileged payload /${payload.asarPath}`);
  }
}

function validateExtractedRuntimePayloads(extractionRoot, manifest, label) {
  const resolvedRoot = path.resolve(extractionRoot);
  for (const payload of manifest.runtimeBuild.payloads) {
    const extracted = path.resolve(resolvedRoot, ...payload.asarPath.split("/"));
    if (!extracted.startsWith(`${resolvedRoot}${path.sep}`)) fail(`${label} runtime payload escapes extracted ASAR: ${payload.asarPath}`);
    if (!existsSync(extracted)) fail(`${label} app.asar is missing attested runtime payload /${payload.asarPath}`);
    const stat = lstatSync(extracted);
    if (!stat.isFile()) fail(`${label} attested runtime payload is not a regular file: /${payload.asarPath}`);
    if (stat.size !== payload.size) {
      fail(`${label} runtime payload size mismatch for /${payload.asarPath}: manifest=${payload.size}, ASAR=${stat.size}`);
    }
    const actualHash = sha256(extracted);
    if (actualHash !== payload.sha256) {
      fail(`${label} runtime payload SHA-256 mismatch for /${payload.asarPath}: manifest=${payload.sha256}, ASAR=${actualHash}`);
    }
  }
}

function validateExtractedPrivilegedPayloads(extractionRoot, manifest, label) {
  const resolvedRoot = path.resolve(extractionRoot);
  for (const payload of manifest.privilegedPayloads) {
    const extracted = path.resolve(resolvedRoot, ...payload.asarPath.split("/"));
    if (!extracted.startsWith(`${resolvedRoot}${path.sep}`)) fail(`${label} privileged payload escapes extracted ASAR: ${payload.asarPath}`);
    if (!existsSync(extracted)) fail(`${label} app.asar is missing attested privileged payload /${payload.asarPath}`);
    const stat = lstatSync(extracted);
    if (!stat.isFile()) fail(`${label} attested privileged payload is not a regular file: /${payload.asarPath}`);
    if (stat.size !== payload.size) {
      fail(`${label} privileged payload size mismatch for /${payload.asarPath}: manifest=${payload.size}, ASAR=${stat.size}`);
    }
    const actualHash = sha256(extracted);
    if (actualHash !== payload.sha256) {
      fail(`${label} privileged payload SHA-256 mismatch for /${payload.asarPath}: manifest=${payload.sha256}, ASAR=${actualHash}`);
    }
  }
}

function assertManifestMatchesSnapshot(manifest, snapshot, label) {
  if (manifest.fingerprint !== snapshot.fingerprint) {
    fail(`${label} source fingerprint ${manifest.fingerprint} does not match current source ${snapshot.fingerprint}`);
  }
  if (manifest.entryCount !== snapshot.entryCount) {
    fail(`${label} source entryCount ${manifest.entryCount} does not match current source ${snapshot.entryCount}`);
  }
  if (manifest.dirty !== snapshot.dirty) {
    fail(`${label} dirty marker ${manifest.dirty} does not match current source ${snapshot.dirty}`);
  }
  if (manifest.head !== snapshot.head) {
    fail(`${label} Git head ${manifest.head} does not match current source ${snapshot.head}`);
  }
  if (JSON.stringify(manifest.privilegedPayloads) !== JSON.stringify(snapshot.privilegedPayloads)) {
    fail(`${label} privileged Electron payload attestation does not match current source`);
  }
}

function assertManifestMatchesRuntimeBuild(manifest, runtimeBuild, label) {
  if (JSON.stringify(manifest.runtimeBuild) !== JSON.stringify(runtimeBuild)) {
    fail(`${label} runtime build attestation does not match the compiled payloads in the current source checkout`);
  }
}

function extractAppImage(file, root) {
  const target = path.join(root, "appimage");
  mkdirSync(target);
  run(file, ["--appimage-extract"], { cwd: target });
  return path.join(target, "squashfs-root");
}

function extractDeb(file, root) {
  const target = path.join(root, "deb-data");
  const controlTarget = path.join(root, "deb-control");
  const archive = path.join(root, "deb-ar");
  mkdirSync(target);
  mkdirSync(controlTarget);
  mkdirSync(archive);
  run("ar", ["x", file], { cwd: archive });
  const dataArchive = ["data.tar.zst", "data.tar.xz", "data.tar.gz", "data.tar.bz2"].map((name) => path.join(archive, name)).find(existsSync);
  if (!dataArchive) fail("DEB is missing a supported data.tar archive");
  run("tar", ["-xf", dataArchive, "-C", target]);
  const controlArchive = ["control.tar.zst", "control.tar.xz", "control.tar.gz", "control.tar.bz2"].map((name) => path.join(archive, name)).find(existsSync);
  if (!controlArchive) fail("DEB is missing a supported control.tar archive");
  run("tar", ["-xf", controlArchive, "-C", controlTarget]);
  return { target, controlTarget };
}

function firstMatching(root, predicate, label) {
  const matches = walk(root, predicate);
  if (matches.length !== 1) fail(`${label}: expected exactly one match, found ${matches.length}`);
  return matches[0];
}

function topLevelMatching(root, predicate, label) {
  const matches = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && predicate(entry.name))
    .map((entry) => path.join(root, entry.name));
  if (matches.length !== 1) fail(`${label}: expected exactly one match, found ${matches.length}`);
  return matches[0];
}

function validateRecoverableSourceSnapshot(releaseDir, manifest, label) {
  const topLevelReleaseFiles = readdirSync(releaseDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(releaseDir, entry.name));
  const sourceArchives = topLevelReleaseFiles.filter((file) => /^JanjaCord-source-[a-f0-9]{64}\.tar$/.test(path.basename(file)));
  const sourceDigests = topLevelReleaseFiles.filter((file) => /^JanjaCord-source-[a-f0-9]{64}\.tar\.sha256$/.test(path.basename(file)));
  if (manifest.dirty) {
    if (sourceArchives.length !== 1 || sourceDigests.length !== 1) fail(`${label} dirty release must contain exactly one recoverable source snapshot and digest`);
    const validatedSnapshot = validateSourceSnapshotArtifact(sourceArchives[0], manifest.sourceSnapshot);
    if (validatedSnapshot.digestPath !== sourceDigests[0]) fail(`${label} dirty source snapshot digest path does not match the release artifact`);
  } else if (sourceArchives.length !== 0 || sourceDigests.length !== 0) {
    fail(`${label} clean release contains an unexpected dirty source snapshot artifact`);
  }
}

function validatePackagedProvenance(asarPath, label, releaseDir, asarCli, temp) {
  const asar = validateAsar(asarPath, label, asarCli);
  const extractedAsar = extractAsar(asar.path, label, asarCli, temp);
  const manifest = readExtractedSourceManifest(extractedAsar, label);
  validateRecoverableSourceSnapshot(releaseDir, manifest, label);
  requireAttestedPayloadEntries(asar.entries, manifest, label);
  validateExtractedRuntimePayloads(extractedAsar, manifest, label);
  validateExtractedPrivilegedPayloads(extractedAsar, manifest, label);
  const currentSource = computeSourceSnapshot(workspaceRoot);
  assertManifestMatchesSnapshot(manifest, currentSource, label);
  const currentRuntimeBuild = computeRuntimeBuildAttestation(workspaceRoot, discoverRuntimeWorkspacePlan(workspaceRoot));
  assertManifestMatchesRuntimeBuild(manifest, currentRuntimeBuild, label);
  return { asar, extractedAsar, manifest };
}

function validateLinuxArtifacts(releaseDir) {
  const appImage = firstMatching(releaseDir, (file) => /\.AppImage$/.test(file), "AppImage artifact");
  const deb = firstMatching(releaseDir, (file) => /\.deb$/.test(file), "DEB artifact");
  const budgets = { appImage: 220 * 1024 * 1024, deb: 170 * 1024 * 1024 };
  if (statSync(appImage).size > budgets.appImage) fail(`AppImage exceeds 220 MiB: ${statSync(appImage).size} bytes`);
  if (statSync(deb).size > budgets.deb) fail(`DEB exceeds 170 MiB: ${statSync(deb).size} bytes`);

  const temp = mkdtempSync(path.join(os.tmpdir(), "janjacord-artifacts-"));
  try {
    const asarCli = findAsarCli();
    const appImageRoot = extractAppImage(appImage, temp);
    const { target: debRoot, controlTarget: debControlRoot } = extractDeb(deb, temp);
    const appImageAsar = validateAsar(firstMatching(appImageRoot, (file) => file.split(path.sep).join("/").endsWith("/resources/app.asar"), "AppImage ASAR"), "AppImage", asarCli);
    const debAsar = validateAsar(firstMatching(debRoot, (file) => file.split(path.sep).join("/").endsWith("/resources/app.asar"), "DEB ASAR"), "DEB", asarCli);
    if (sha256(appImageAsar.path) !== sha256(debAsar.path)) fail("AppImage and DEB contain different app.asar payloads");

    const appImageExtractedAsar = extractAsar(appImageAsar.path, "AppImage", asarCli, temp);
    const debExtractedAsar = extractAsar(debAsar.path, "DEB", asarCli, temp);
    const appImageManifest = readExtractedSourceManifest(appImageExtractedAsar, "AppImage");
    const debManifest = readExtractedSourceManifest(debExtractedAsar, "DEB");
    if (JSON.stringify(appImageManifest) !== JSON.stringify(debManifest)) fail("AppImage and DEB contain different source provenance manifests");
    validateRecoverableSourceSnapshot(releaseDir, appImageManifest, "AppImage/DEB");
    requireAttestedPayloadEntries(appImageAsar.entries, appImageManifest, "AppImage");
    requireAttestedPayloadEntries(debAsar.entries, debManifest, "DEB");
    validateExtractedRuntimePayloads(appImageExtractedAsar, appImageManifest, "AppImage");
    validateExtractedRuntimePayloads(debExtractedAsar, debManifest, "DEB");
    validateExtractedPrivilegedPayloads(appImageExtractedAsar, appImageManifest, "AppImage");
    validateExtractedPrivilegedPayloads(debExtractedAsar, debManifest, "DEB");
    const currentSource = computeSourceSnapshot(workspaceRoot);
    assertManifestMatchesSnapshot(appImageManifest, currentSource, "AppImage/DEB");
    const currentRuntimeBuild = computeRuntimeBuildAttestation(workspaceRoot, discoverRuntimeWorkspacePlan(workspaceRoot));
    assertManifestMatchesRuntimeBuild(appImageManifest, currentRuntimeBuild, "AppImage/DEB");

    for (const [label, root] of [["AppImage", appImageRoot], ["DEB", debRoot]]) {
      firstMatching(root, (file) => /\/janjacord\.desktop$/i.test(file), `${label} desktop entry`);
      const icon = firstMatching(root, (file) => /\/icons\/hicolor\/512x512\/apps\/.+\.png$/.test(file), `${label} 512px icon`);
      if (sha256(icon) !== sha256(path.join(appDir, "build/icon.png"))) fail(`${label} packaged icon differs from build/icon.png`);
      firstMatching(root, (file) => file.endsWith("/resources/janjacord-cleanup-autostart"), `${label} per-user cleanup helper`);
    }
    for (const hook of walk(debControlRoot, (file) => /\/(postinst|prerm|postrm|preinst)$/.test(file))) {
      const text = readFileSync(hook, "utf8");
      if (/ufw|firewall-cmd|netsh|autostart|\/home\/\*|getent\s+passwd|\/etc\/passwd/i.test(text)) fail(`DEB contains a forbidden global lifecycle hook: ${hook}`);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }

  console.log(`desktop artifacts valid: AppImage=${statSync(appImage).size} bytes, DEB=${statSync(deb).size} bytes`);
}

function windowsSignatureStatus(file) {
  if (process.platform !== "win32") fail("Windows artifact signature validation must run on Windows");
  const escaped = file.replace(/'/g, "''");
  const command = `(Get-AuthenticodeSignature -LiteralPath '${escaped}').Status.ToString()`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], {
    cwd: workspaceRoot,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) fail(`Authenticode inspection failed: ${(result.stderr || result.error?.message || "").trim()}`);
  return result.stdout.trim();
}

function validateWindowsArtifacts(releaseDir, expectedSignature) {
  if (!["unsigned", "valid"].includes(expectedSignature)) fail("Windows artifact validation requires --windows-signature unsigned or valid");
  const installer = topLevelMatching(releaseDir, (name) => name.toLowerCase().endsWith(".exe"), "Windows NSIS installer");
  if (statSync(installer).size > 250 * 1024 * 1024) fail(`Windows installer exceeds 250 MiB: ${statSync(installer).size} bytes`);
  const expectedStatus = expectedSignature === "unsigned" ? "NotSigned" : "Valid";
  const actualStatus = windowsSignatureStatus(installer);
  if (actualStatus !== expectedStatus) fail(`Windows installer signature must be ${expectedStatus}, got ${actualStatus}`);

  const unpackedExecutable = path.join(releaseDir, "win-unpacked", `${packageJson.build?.executableName ?? packageJson.build?.productName}.exe`);
  if (!existsSync(unpackedExecutable) || !lstatSync(unpackedExecutable).isFile()) fail("Windows unpacked application executable is missing");
  const unpackedStatus = windowsSignatureStatus(unpackedExecutable);
  if (unpackedStatus !== expectedStatus) fail(`Windows application executable signature must be ${expectedStatus}, got ${unpackedStatus}`);

  const unpackedAsar = firstMatching(releaseDir, (file) => file.split(path.sep).join("/").endsWith("/win-unpacked/resources/app.asar"), "Windows unpacked ASAR");
  const temp = mkdtempSync(path.join(os.tmpdir(), "janjacord-windows-artifacts-"));
  try {
    const asarCli = findAsarCli();
    validatePackagedProvenance(unpackedAsar, "Windows", releaseDir, asarCli, temp);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
  console.log(`desktop Windows artifact valid: installer=${statSync(installer).size} bytes, installerSignature=${actualStatus}, appSignature=${unpackedStatus}`);
}

function runSelfTest() {
  runSourceFingerprintSelfTest();
  const fixturePayloads = [
    {
      workspace: "@janjacord/desktop",
      sourcePath: "apps/desktop/dist/index.html",
      asarPath: "dist/index.html",
      content: Buffer.from("<!doctype html><title>fixture</title>\n"),
    },
    {
      workspace: "@janjacord/janjanode",
      sourcePath: "apps/janjanode/dist/main.js",
      asarPath: "node_modules/@janjacord/janjanode/dist/main.js",
      content: Buffer.from("console.log('fixture runtime');\n"),
    },
  ];
  const fixturePrivilegedPayloads = [
    {
      sourcePath: "apps/desktop/electron/main.mjs",
      asarPath: "electron/main.mjs",
      content: Buffer.from("console.log('privileged main fixture');\n"),
    },
    {
      sourcePath: "apps/desktop/electron/preload.cjs",
      asarPath: "electron/preload.cjs",
      content: Buffer.from("module.exports = 'privileged preload fixture';\n"),
    },
  ];
  const snapshot = {
    fingerprint: "a".repeat(64),
    head: "b".repeat(40),
    dirty: true,
    entryCount: 7,
    privilegedPayloads: fixturePrivilegedPayloads.map(({ content, ...payload }) => ({
      ...payload,
      size: content.length,
      sha256: sha256Content(content),
    })),
  };
  const runtimeBuild = {
    command: [...RUNTIME_BUILD_COMMAND],
    rootWorkspace: RUNTIME_BUILD_ROOT_WORKSPACE,
    payloadHashAlgorithm: "sha256",
    workspaces: [
      { name: "@janjacord/desktop", packagePath: "apps/desktop", outputRoots: ["dist"] },
      { name: "@janjacord/janjanode", packagePath: "apps/janjanode", outputRoots: ["dist"] },
    ],
    payloads: fixturePayloads.map(({ content, ...payload }) => ({
      ...payload,
      size: content.length,
      sha256: sha256Content(content),
    })).sort((left, right) => Buffer.compare(Buffer.from(left.asarPath), Buffer.from(right.asarPath))),
  };
  const sourceSnapshot = {
    format: "ustar",
    filename: `JanjaCord-source-${snapshot.fingerprint}.tar`,
    digestFilename: `JanjaCord-source-${snapshot.fingerprint}.tar.sha256`,
    sha256: "c".repeat(64),
    metadataFilename: "janjacord-source-snapshot.json",
    contentRoot: "source",
    fingerprint: snapshot.fingerprint,
    head: snapshot.head,
    entryCount: snapshot.entryCount,
  };
  const manifest = createSourceManifest(snapshot, { sourceFrozen: true, reviewedDirtySnapshot: true, runtimeBuild, sourceSnapshot });
  validateSourceManifest(manifest, "validator self-test manifest");
  assertManifestMatchesSnapshot(manifest, snapshot, "validator self-test");
  assertManifestMatchesRuntimeBuild(manifest, runtimeBuild, "validator self-test");

  const temp = mkdtempSync(path.join(os.tmpdir(), "janjacord-validator-self-test-"));
  try {
    const fixtureRoot = path.join(temp, "fixture");
    const fixtureDist = path.join(fixtureRoot, "dist");
    const fixtureAsar = path.join(temp, "fixture.asar");
    mkdirSync(fixtureDist, { recursive: true });
    for (const payload of fixturePayloads) {
      const fixturePayload = path.join(fixtureRoot, ...payload.asarPath.split("/"));
      mkdirSync(path.dirname(fixturePayload), { recursive: true });
      writeFileSync(fixturePayload, payload.content);
    }
    for (const payload of fixturePrivilegedPayloads) {
      const fixturePayload = path.join(fixtureRoot, ...payload.asarPath.split("/"));
      mkdirSync(path.dirname(fixturePayload), { recursive: true });
      writeFileSync(fixturePayload, payload.content);
    }
    writeFileSync(path.join(fixtureDist, SOURCE_MANIFEST_FILENAME), `${JSON.stringify(manifest)}\n`, "utf8");
    const asarCli = findAsarCli();
    run(process.execPath, [asarCli, "pack", fixtureRoot, fixtureAsar]);
    const extractedRoot = extractAsar(fixtureAsar, "self-test", asarCli, temp);
    const extractedManifest = readExtractedSourceManifest(extractedRoot, "self-test");
    assertManifestMatchesSnapshot(extractedManifest, snapshot, "extracted validator self-test");
    validateExtractedRuntimePayloads(extractedRoot, extractedManifest, "self-test");
    validateExtractedPrivilegedPayloads(extractedRoot, extractedManifest, "self-test");

    for (const payload of fixturePrivilegedPayloads) {
      const tamperedPayload = path.join(extractedRoot, ...payload.asarPath.split("/"));
      const tamperedContent = Buffer.from(payload.content);
      tamperedContent[0] ^= 0xff;
      writeFileSync(tamperedPayload, tamperedContent);
      let tamperedPayloadRejection;
      try {
        validateExtractedPrivilegedPayloads(extractedRoot, extractedManifest, `tampered ${payload.asarPath} fixture`);
      } catch (error) {
        tamperedPayloadRejection = error;
      }
      if (!tamperedPayloadRejection?.message.includes("privileged payload SHA-256 mismatch")) {
        fail(`validator self-test accepted same-size tampering of privileged payload /${payload.asarPath}`);
      }
      writeFileSync(tamperedPayload, payload.content);
    }

    const forgedPayload = fixturePrivilegedPayloads[0];
    const forgedPayloadPath = path.join(extractedRoot, ...forgedPayload.asarPath.split("/"));
    const forgedContent = Buffer.from(forgedPayload.content);
    forgedContent[0] ^= 0xff;
    writeFileSync(forgedPayloadPath, forgedContent);
    const forgedManifest = structuredClone(extractedManifest);
    forgedManifest.privilegedPayloads[0].sha256 = sha256Content(forgedContent);
    validateSourceManifest(forgedManifest, "forged privileged fixture manifest");
    validateExtractedPrivilegedPayloads(extractedRoot, forgedManifest, "forged privileged fixture");
    let forgedManifestRejection;
    try {
      assertManifestMatchesSnapshot(forgedManifest, snapshot, "forged privileged fixture");
    } catch (error) {
      forgedManifestRejection = error;
    }
    if (!forgedManifestRejection?.message.includes("privileged Electron payload attestation does not match current source")) {
      fail("validator self-test accepted coordinated tampering of a privileged payload and its manifest hash");
    }
    writeFileSync(forgedPayloadPath, forgedPayload.content);

    const missingPrivilegedPayload = path.join(extractedRoot, ...fixturePrivilegedPayloads[1].asarPath.split("/"));
    rmSync(missingPrivilegedPayload);
    let missingPrivilegedRejection;
    try {
      validateExtractedPrivilegedPayloads(extractedRoot, extractedManifest, "missing privileged fixture");
    } catch (error) {
      missingPrivilegedRejection = error;
    }
    if (!missingPrivilegedRejection?.message.includes("missing attested privileged payload")) {
      fail("validator self-test accepted a missing privileged payload");
    }
    writeFileSync(missingPrivilegedPayload, fixturePrivilegedPayloads[1].content);

    const tamperedPayload = path.join(extractedRoot, ...fixturePayloads[1].asarPath.split("/"));
    const tamperedContent = Buffer.from(fixturePayloads[1].content);
    tamperedContent[0] ^= 0xff;
    writeFileSync(tamperedPayload, tamperedContent);
    let tamperedPayloadRejection;
    try {
      validateExtractedRuntimePayloads(extractedRoot, extractedManifest, "tampered fixture");
    } catch (error) {
      tamperedPayloadRejection = error;
    }
    if (!tamperedPayloadRejection?.message.includes("runtime payload SHA-256 mismatch")) fail("validator self-test accepted a same-size tampered runtime payload");

    rmSync(tamperedPayload);
    let missingPayloadRejection;
    try {
      validateExtractedRuntimePayloads(extractedRoot, extractedManifest, "missing fixture");
    } catch (error) {
      missingPayloadRejection = error;
    }
    if (!missingPayloadRejection?.message.includes("missing attested runtime payload")) fail("validator self-test accepted a missing runtime payload");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }

  let missingManifestRejection;
  try {
    requireAsarEntries(["/electron/main.mjs", "/electron/preload.cjs", "/dist/index.html", "/package.json"], "legacy fixture");
  } catch (error) {
    missingManifestRejection = error;
  }
  if (!missingManifestRejection?.message.includes(SOURCE_MANIFEST_FILENAME)) fail("validator self-test accepted an app.asar without a source manifest");

  let incompletePrivilegedManifestRejection;
  try {
    const incompletePrivilegedManifest = structuredClone(manifest);
    incompletePrivilegedManifest.privilegedPayloads.pop();
    validateSourceManifest(incompletePrivilegedManifest, "incomplete privileged fixture manifest");
  } catch (error) {
    incompletePrivilegedManifestRejection = error;
  }
  if (!incompletePrivilegedManifestRejection?.message.includes("must contain exactly 2 payloads")) {
    fail("validator self-test accepted a manifest that omitted a required privileged payload");
  }

  let staleManifestRejection;
  try {
    assertManifestMatchesSnapshot(manifest, { ...snapshot, fingerprint: "c".repeat(64) }, "stale fixture");
  } catch (error) {
    staleManifestRejection = error;
  }
  if (!staleManifestRejection?.message.includes("does not match current source")) fail("validator self-test accepted a stale source manifest");

  let staleRuntimeRejection;
  try {
    const changedRuntime = structuredClone(runtimeBuild);
    changedRuntime.payloads[0].sha256 = "c".repeat(64);
    assertManifestMatchesRuntimeBuild(manifest, changedRuntime, "stale runtime fixture");
  } catch (error) {
    staleRuntimeRejection = error;
  }
  if (!staleRuntimeRejection?.message.includes("does not match the compiled payloads")) fail("validator self-test accepted a stale runtime build attestation");
  console.log("desktop artifact provenance self-test passed");
}

const platform = option("--platform", "config");
const releaseDir = path.resolve(option("--release-dir", path.join(appDir, "release")));

if (args.includes("--self-test")) {
  if (args.length !== 1) fail("--self-test cannot be combined with other arguments");
  runSelfTest();
  process.exit(0);
}

validatePackageConfig();
validatePackagingWrapperContracts();
validateIcon();
validateRendererCsp();
validateNoGlobalHooks();
validateAutostartContract();
if (platform === "linux") validateLinuxArtifacts(releaseDir);
else if (platform === "windows") validateWindowsArtifacts(releaseDir, option("--windows-signature"));
else if (platform !== "config") fail(`unsupported --platform ${platform}`);
console.log(`desktop release validation passed (${platform})`);
