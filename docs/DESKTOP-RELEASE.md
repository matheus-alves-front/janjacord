# Desktop release path

## Artifact classes

The Windows CI workflow produces an **unsigned test-only** NSIS installer. Its artifact name starts
with `UNSIGNED-TEST-ONLY`, retention is seven days, and CI verifies Authenticode status is
`NotSigned`. Do not publish that artifact, point auto-update at it, or present it as a release.

The package has no `publish` provider configured. This is intentional: the previous example-domain
updater configuration could generate metadata for an endpoint that does not exist. A future update
channel needs a real owner, authenticated upload path, HTTPS origin, rollback policy and signature
verification before `publish` is restored.

Generic `pnpm --filter @janjacord/desktop dist` also fails intentionally: packaging must name the
platform and, on Windows, whether the artifact is unsigned test-only or signed release.

## Firewall behavior

Desktop installation and uninstall do not write Windows Defender Firewall, ufw or firewalld rules.
The normal WAN path is outbound WSS/WebRTC/TURN. AppImage must never mutate host firewall state, and
DEB/NSIS installation must not expose JanjaNode port 8931 globally.

An operator who deliberately enables direct inbound LAN hosting owns that host-level configuration
outside the installer and should scope it to the intended interface/source network. Because the
installer creates no rule, uninstall has nothing to remove and cannot delete an unrelated rule with
a matching display name.

## Windows test artifact

After source freeze, run locally on Windows or dispatch `.github/workflows/windows-unsigned-test.yml`:

```powershell
pnpm install --frozen-lockfile
pnpm --filter @janjacord/desktop typecheck
$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
$env:JANJACORD_SOURCE_FROZEN = "1"
pnpm --filter @janjacord/desktop run validate:release-config
pnpm --filter @janjacord/desktop run dist:win:test
Get-AuthenticodeSignature apps/desktop/release/*.exe
```

Expected result: an NSIS `.exe` whose signature status is `NotSigned`. It is suitable only for
installation/uninstall QA in an isolated test machine.

The guarded Windows wrapper uses the same source freeze, source fingerprint, recoverable dirty
snapshot, runtime-payload provenance and ASAR-content validation model as Linux. It builds into a
staging directory and publishes `apps/desktop/release` only after every gate passes. A dirty local
candidate additionally requires `JANJACORD_REVIEWED_DIRTY_SNAPSHOT=1`; CI packages a clean checkout.
Those two markers are a deliberate dual authorization, not alternatives. For a reviewed dirty
Windows test candidate, set both in the same release shell before invoking the wrapper:

```powershell
$env:JANJACORD_SOURCE_FROZEN = "1"
$env:JANJACORD_REVIEWED_DIRTY_SNAPSHOT = "1"
pnpm --filter @janjacord/desktop run dist:win:test
```

The dirty snapshot remains provenance evidence only; it is not signing or release approval.
Windows runner execution and installation QA remain external gates.

## Production Windows signing gate

Production packaging must run only in a trusted release environment with signing credentials
injected from its secret store. Never commit a PFX/P12 or password. The release command is:

```powershell
$env:JANJACORD_SOURCE_FROZEN = "1"
pnpm --filter @janjacord/desktop run dist:win:release
```

The guarded wrapper passes `forceCodeSigning=true`, validates the packaged ASAR/provenance, and
requires Authenticode status `Valid`; missing or invalid credentials fail instead of silently
creating an unsigned release. After packaging, independently require:

```powershell
$artifact = Get-ChildItem apps/desktop/release -File -Filter *.exe
if (-not $artifact) { throw "installer missing" }
$artifact | ForEach-Object {
  $signature = Get-AuthenticodeSignature $_.FullName
  if ($signature.Status -ne "Valid") { throw "invalid signature: $($_.Name)" }
}
```

Publishing remains a separate, explicitly authorized step after signature, clean-install,
upgrade, autostart opt-in and uninstall validation on real Windows.

## Linux autostart lifecycle

Hosting autostart is opt-in and belongs to the logged-in user. On Linux the app writes only
`${XDG_CONFIG_HOME:-$HOME/.config}/autostart/janjacord.desktop`; neither DEB installation nor
uninstall creates, edits or searches user homes. This is intentional: package maintainer scripts
run without a reliable desktop-user identity, and enumerating `/home`, `/etc/passwd` or NSS users
would risk deleting another account's or operator-owned configuration.

For AppImage, the desktop entry must point to Electron's `APPIMAGE` environment path, which is the
persistent file the user launched. `app.getPath("exe")` can resolve inside a temporary AppImage
mount and is forbidden by the release validator. The entry also carries `TryExec` and
`X-JanjaCord-Autostart=true`: a moved/deleted AppImage fails inertly, and cleanup removes only an
entry positively identified as JanjaCord-owned.

Before deleting an AppImage or uninstalling the DEB, the normal cleanup path is to disable
"Hospedagem em segundo plano" inside JanjaCord. For a current-user repair, while the DEB is still
installed, run:

```bash
/opt/JanjaCord/resources/janjacord-cleanup-autostart
```

From a source checkout the equivalent is:

```bash
pnpm --filter @janjacord/desktop run cleanup:linux-autostart
```

The helper refuses symlinks, non-regular files, entries outside the current user's home and files
without the JanjaCord ownership marker plus `--background-host`. It never uses sudo and never
enumerates users. Package uninstall therefore leaves a manually enabled entry in place if the user
skips cleanup; `TryExec` prevents launch after the binary disappears. This residual is preferable
to unsafe cross-user deletion by a global uninstall hook.

## Linux packaging gate and Fedora prerequisite

Use the following only after the owners of Electron main/preload, renderer and JanjaNode declare a
source freeze. The wrapper refuses unless `JANJACORD_SOURCE_FROZEN=1`. A clean worktree is the
normal release input:

```bash
pnpm install --frozen-lockfile
pnpm --filter @janjacord/desktop typecheck
pnpm --filter @janjacord/desktop run validate:release-config
JANJACORD_SOURCE_FROZEN=1 pnpm --filter @janjacord/desktop run dist:linux
```

If an exceptional local candidate must be built from a dirty tree, review every tracked and
untracked non-ignored source input first and provide both authorizations in the same command:

```bash
JANJACORD_SOURCE_FROZEN=1 JANJACORD_REVIEWED_DIRTY_SNAPSHOT=1 \
  pnpm --filter @janjacord/desktop run dist:linux
```

`JANJACORD_REVIEWED_DIRTY_SNAPSHOT=1` without `JANJACORD_SOURCE_FROZEN=1` is rejected, as is a dirty
tree with only the freeze marker. The resulting recoverable snapshot attests provenance; it does
not claim CI execution, signing or release approval.

On Fedora, run the preflight before packaging:

```bash
node apps/desktop/scripts/check-linux-packaging-host.mjs
```

If it reports missing `libcrypt.so.1`, install Fedora's compatibility package once:

```bash
sudo dnf install libxcrypt-compat
```

This is a build-host dependency for electron-builder's bundled `fpm` Ruby, not a JanjaCord runtime
dependency and not a reason to modify application code. The preflight reports the exact command but
does not invoke sudo or mutate the host.

`dist:linux` validates configuration and host prerequisites before the runtime build, builds both
targets in an ignored staging directory, and then runs the fail-closed artifact validator. Only a
fully validated staging directory is renamed to `release`; failure removes the complete staging
tree, including unpacked output and electron-builder metadata. The validator
requires exactly one AppImage and one DEB, extracts both, checks the same ASAR digest/content,
512x512 packaged icon, packaged per-user cleanup helper, absence of firewall/global-user hooks and
size ceilings (AppImage 220 MiB, DEB 170 MiB, ASAR 160 MiB). Every existing entry must be moved out
of `apps/desktop/release` before a local release run; the wrapper never mixes old and new outputs.
`.github/workflows/linux-packaging-test.yml` performs the same gate on a clean immutable CI checkout
and uploads seven-day test-only artifacts with SHA-256 checksums.

`apps/desktop/build/icon.png` and `icon.svg` are tracked release source inputs despite the surrounding
generated `build/` directory. The source snapshot uses an explicit code/config root allowlist and
rejects local database, SQLite sidecar, vault, backup archive, token, credential, key and secret
artifacts. It excludes project memory, build output, dependencies and release evidence.

Validate both AppImage and DEB on every supported distribution before publishing. Bind the clean
install/remove transcript to the exact DEB SHA-256 in the release dossier: verify package state,
binary, launcher and desktop entry, then verify that `apt-get remove` removes all three payloads and
leaves at most the normal `config-files` package state. Firewall invariance and autostart across a
real login/reboot remain operator checks.

## Local validation without packaging

While application source is being edited concurrently, do not run `dist:linux`. The safe checks are:

```bash
node --check apps/desktop/scripts/*.mjs
sh -n apps/desktop/scripts/janjacord-cleanup-autostart
pnpm --filter @janjacord/desktop run validate:release-config
```

The last command validates the tracked icon inputs, source-snapshot policy, renderer CSP, package
configuration and the `APPIMAGE`/`TryExec`/ownership-marker contract before any expensive build. Do
not bypass a failure to package a candidate.

## Packaged UI gallery evidence

Do not rebuild a package just to refresh gallery evidence. After a validated AppImage already
exists, run that exact executable with the packaged UI smoke enabled and a new empty evidence
directory:

```bash
mkdir -p artifacts/ui-gallery
JC_SMOKE_UI=1 JC_SMOKE_DIR="$PWD/artifacts/ui-gallery" \
  ./apps/desktop/release/JanjaCord-0.1.0-x86_64.AppImage
```

A successful packaged run writes the screenshots plus
`artifacts/ui-gallery/jc-ui-gallery-execution.json`. The manifest records the executable filename,
its SHA-256, execution timestamps, result, and a SHA-256 for every screenshot captured in that run.
Bind review of the gallery to `executableSha256`; screenshots without this manifest do not prove
which packaged executable produced them. Development-mode `electron .` runs intentionally do not
claim packaged provenance and therefore do not emit this manifest.
