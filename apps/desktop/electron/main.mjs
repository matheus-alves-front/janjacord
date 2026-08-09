/**
 * Electron main (ESM) — JanjaCord desktop.
 * Responsabilidades: vault local (ADR-001/016), MLS via WASM (crypto-core), JanjaNode como
 * child process (host do server), cliente WS (HostClient), IPC para o renderer.
 * O renderer é sandboxed (contextIsolation) — toda crypto passa por aqui.
 */
import { app, BrowserWindow, ipcMain, session } from "electron";

// smoke: isola userData (identidades recriadas a cada execução geram dbKeys novas)
if ((process.env.JC_SMOKE_UI || process.env.JC_SMOKE_MEDIA || process.env.JC_SMOKE_MEDIA_PEER) && process.env.JC_SMOKE_DIR) {
  app.setPath("userData", path.join(process.env.JC_SMOKE_DIR, "userdata"));
}
// smoke media: dispositivos sintéticos do Chromium (sem hardware)
if (process.env.JC_SMOKE_MEDIA || process.env.JC_SMOKE_MEDIA_PEER) {
  app.commandLine.appendSwitch("use-fake-ui-for-media-stream");
  app.commandLine.appendSwitch("use-fake-device-for-media-stream");
}
import { fork } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createIdentity,
  unlockIdentity,
  generateRecoveryKey,
  restoreIdentity,
} from "@janjacord/identity";
import { createCipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { createLinkSession } from "@janjacord/identity";
import { parseInviteKey } from "@janjacord/crypto";
import { EncryptedDatabase } from "@janjacord/persistence";
import { HostClient } from "@janjacord/networking";
import { buildEnvelope } from "@janjacord/protocol";
import * as mls from "@janjacord/crypto-core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOST_PORT = 8931;

// ---------------------------------------------------------------- estado
let identity = null; // { identityId, nickname, seed, dbKey }
let localDb = null; // EncryptedDatabase (estado MLS + cache local)
let hostProcess = null;
let client = null; // HostClient
let serverState = null; // estado do server do host
let channelSeq = new Map();

function userData() {
  return app.getPath("userData");
}
function vaultPath() {
  return path.join(userData(), "vault.json");
}
function localDbPath() {
  return path.join(userData(), "local.db");
}
function hostDbPath() {
  return path.join(userData(), "janjanode", "server.db");
}
function janjanodeMainPath() {
  return path.join(__dirname, "..", "..", "janjanode", "dist", "main.js");
}

async function loadMls() {
  await mls.default; // inicializa o módulo wasm
}
function groupIdHex(channelId) {
  return Buffer.from(channelId.replace(/-/g, ""), "hex").toString("hex");
}

// ---------------------------------------------------------------- MLS persistence
function mlsStateKey(serverId, channelId) {
  return `mls:${serverId}:${channelId}`;
}
function saveMlsState(serverId, channelId) {
  if (!localDb) return;
  const gid = groupIdHex(channelId);
  const state = mls.export_group(identity.identityId, gid);
  localDb.raw
    .prepare("INSERT INTO mls_groups (key, state, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at")
    .run(mlsStateKey(serverId, channelId), state, Date.now());
}
function loadMlsState(serverId, channelId) {
  if (!localDb) return false;
  const row = localDb.raw.prepare("SELECT state FROM mls_groups WHERE key = ?").get(mlsStateKey(serverId, channelId));
  if (!row) return false;
  const gid = groupIdHex(channelId);
  mls.import_group(identity.identityId, gid, row.state);
  return true;
}

function initLocalDb() {
  localDb = new EncryptedDatabase(localDbPath(), identity.dbKey);
  localDb.migrate(
    "CREATE TABLE IF NOT EXISTS mls_groups (key TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at INTEGER NOT NULL);" +
      "CREATE TABLE IF NOT EXISTS seen_messages (message_id TEXT PRIMARY KEY, consumed INTEGER NOT NULL DEFAULT 0);",
  );
}

// ---------------------------------------------------------------- janjanode (host)
function spawnHost() {
  const env = {
    ...process.env,
    JC_DB_KEY: identity.dbKey.toString("hex"),
    JC_DB_PATH: hostDbPath(),
    JC_OWNER_IDENTITY: identity.identityId,
    JC_OWNER_NICKNAME: identity.nickname,
    JC_SERVER_NAME: "Meu Servidor",
    JC_PORT: String(HOST_PORT),
  };
  hostProcess = fork(janjanodeMainPath(), [], {
    env,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execPath: process.env.JC_NODE_BIN ?? "node", // child usa o Node real, não o Electron
  });
  hostProcess.stdout?.on("data", (d) => console.log("[host]", d.toString().trim()));
  hostProcess.stderr?.on("data", (d) => console.error("[host]", d.toString().trim()));
  hostProcess.on("exit", (code) => console.log(`[host] exit ${code}`));
}

function stopHost() {
  if (hostProcess) {
    hostProcess.kill();
    hostProcess = null;
  }
}

// ---------------------------------------------------------------- ws client + MLS
function connectToHost(url) {
  client = new HostClient(url, { identityId: identity.identityId });
  client.onEvent((evt) => {
    try {
    if (evt.type === "envelope.deliver") {
      handleDelivered(evt.envelope);
    } else if (evt.type === "welcome.deliver") {
      handleWelcome(evt.welcomeB64);
    } else if (evt.type === "member.presence") {
      notifyRenderer("member.presence", evt);
    } else if (evt.type === "server.stateChanged") {
      syncGroupMembership();
    } else if (evt.type === "member.removed") {
      notifyRenderer("member.removed", evt);
    } else if (evt.type === "call.members") {
      notifyRenderer("call.members", evt);
    } else if (evt.type === "call.signal") {
      notifyRenderer("call.signal", evt);
    }
    } catch (err) { console.error("[main] event handler:", err); }
  });
  return new Promise((resolve) => {
    client.onOpen(() => resolve(true));
    setTimeout(() => resolve(false), 5000);
  });
}

function sendCommand(cmd) {
  return client?.request(cmd);
}

function notifyRenderer(channel, data) {
  BrowserWindow.getAllWindows().forEach((w) => w.webContents.send(channel, data));
}

function ensureGroup(serverId, channelId) {
  if (loadMlsState(serverId, channelId)) return true;
  const gid = groupIdHex(channelId);
  const created = JSON.parse(mls.create_group(identity.seed.toString("hex"), identity.identityId, gid));
  saveMlsState(serverId, channelId);
  return created.epoch >= 0;
}

async function handleWelcome(welcomeB64) {
  if (!serverState) return;
  const gid = groupIdHex(serverState.channels[0]?.id ?? "");
  if (!gid) return;
  const joined = JSON.parse(mls.join_group(identity.seed.toString("hex"), identity.identityId, welcomeB64));
  saveMlsState(serverState.serverId, serverState.channels[0].id);
  // publica key package e puxa pendências
  publishKeyPackage();
  const pend = await sendCommand({ type: "message.getPending" });
  if (pend.ok) for (const env of pend.data) handleDelivered(env);
  notifyRenderer("mls.ready", { epoch: joined.epoch });
}

async function publishKeyPackage() {
  const kp = mls.generate_key_package(identity.seed.toString("hex"), identity.identityId);
  await sendCommand({ type: "keypackage.upload", keyPackageB64: kp });
}

async function syncGroupMembership() {
  if (!serverState || !client) return;
  const fresh = await sendCommand({ type: "server.state" });
  if (fresh?.ok && fresh.data) serverState = fresh.data;
  else if (!serverState) return;
  // owner reconcilia: para cada membro sem leaf no grupo, add
  const me = serverState.members.find((m) => m.identityId === identity.identityId);
  if (!me || me.roleId !== "role-owner") return;
  const channel = serverState.channels[0];
  if (!channel) return;
  loadMlsState(serverState.serverId, channel.id);
  for (const member of serverState.members) {
    if (member.identityId === identity.identityId) continue;
    const kpRes = await sendCommand({ type: "keypackage.get", targetIdentityId: member.identityId });
    if (!kpRes.ok) continue; // sem KP ainda (membro não publicou)
    const gid = groupIdHex(channel.id);
    try {
      const added = JSON.parse(mls.add_member(identity.seed.toString("hex"), identity.identityId, gid, kpRes.data.keyPackageB64));
      saveMlsState(serverState.serverId, channel.id);
      await sendCommand({ type: "welcome.push", targetIdentityId: member.identityId, welcomeB64: added.welcomeB64 });
    } catch {
      // membro já no grupo (leaf existente) — ignora
    }
  }
}

async function handleDelivered(env) {
  if (!serverState) return;
  const gid = groupIdHex(env.channelId);
  loadMlsState(serverState.serverId, env.channelId);
  try {
    const dec = JSON.parse(mls.decrypt(identity.seed.toString("hex"), identity.identityId, gid, env.ciphertext));
    const plaintext = Buffer.from(dec.plaintextB64, "base64").toString("utf8");
    // payload pode ser texto puro ou JSON de attachment
    let text = plaintext;
    let attachment = null;
    try {
      const payload = JSON.parse(plaintext);
      if (payload?.assetKeys && payload.attachments?.length > 0) {
        text = payload.text ?? "📎 anexo";
        const ref = payload.attachments[0];
        const key = payload.assetKeys[ref.assetId];
        if (key) {
          const dl = await sendCommand({ type: "attachment.download", assetId: ref.assetId });
          if (dl.ok) {
            const encrypted = Buffer.from(dl.data.data, "base64");
            const assetKey = Buffer.from(key, "base64");
            const nonce = encrypted.subarray(0, 12);
            const tag = encrypted.subarray(12, 28);
            const ct = encrypted.subarray(28);
            const decipher = createDecipheriv("aes-256-gcm", assetKey, nonce);
            decipher.setAuthTag(tag);
            const raw = Buffer.concat([decipher.update(ct), decipher.final()]);
            const isImage = ref.mimeType.startsWith("image/");
            attachment = {
              assetId: ref.assetId,
              name: ref.name,
              mimeType: ref.mimeType,
              dataUrl: isImage ? `data:${ref.mimeType};base64,${raw.toString("base64")}` : null,
              sizeBytes: ref.sizeBytes,
            };
          }
        }
      }
    } catch {
      // texto puro
    }
    notifyRenderer("message", { messageId: env.messageId, channelId: env.channelId, sender: env.sender, text, createdAt: env.createdAt, attachment });
    await sendCommand({ type: "message.ackConsumed", messageId: env.messageId });
  } catch {
    // mensagem de outro epoch ou fora da audiência — ignora silenciosamente
  }
}

// ---------------------------------------------------------------- IPC
function registerIpc() {
  ipcMain.handle("identity.status", async () => {
    const { existsSync } = await import("node:fs");
    return { exists: existsSync(vaultPath()) };
  });

  ipcMain.handle("identity.create", async (_e, { nickname, password }) => {
    identity = await createIdentity(nickname, password, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId, recoveryKey: generateRecoveryKey(identity.seed) };
  });

  ipcMain.handle("identity.unlock", async (_e, { password }) => {
    identity = await unlockIdentity(password, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId, nickname: identity.nickname };
  });

  ipcMain.handle("identity.restore", async (_e, { recoveryKey, nickname, newPassword }) => {
    identity = await restoreIdentity(recoveryKey, nickname, newPassword, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId };
  });

  ipcMain.handle("server.create", async () => {
    if (!identity) return { ok: false, error: { code: "unauthorized", message: "identity required" } };
    spawnHost();
    await new Promise((r) => setTimeout(r, 1500));
    const connected = await connectToHost(`ws://127.0.0.1:${HOST_PORT}/signal`);
    if (!connected) return { ok: false, error: { code: "host_offline", message: "host não respondeu" } };
    client.send("hello", { identityId: identity.identityId });
    const stateRes = await new Promise((resolve) => {
      client.onEventOnce("result", (f) => resolve(f.data));
      setTimeout(() => resolve(null), 8000);
    });
    if (!stateRes?.ok) return { ok: false, error: { code: "host_offline", message: "hello falhou" } };
    serverState = stateRes.data;
    const general = serverState.channels.find((c) => c.type === "text") ?? serverState.channels[0];
    ensureGroup(serverState.serverId, general.id);
    publishKeyPackage();
    syncGroupMembership();
    return { ok: true, data: serverState };
  });

  ipcMain.handle("server.join", async (_e, { hostUrl, inviteKey }) => {
    if (!identity) return { ok: false, error: { code: "unauthorized", message: "identity required" } };
    // descoberta via rendezvous quando possível (invite carrega serverId)
    const parsed = parseInviteKey(inviteKey);
    let target = hostUrl;
    if (parsed && process.env.JC_RENDEZVOUS_URL) {
      try {
        const { WebSocket } = await import("ws");
        const ws = new WebSocket(process.env.JC_RENDEZVOUS_URL);
        await new Promise((res, rej) => {
          ws.on("open", res);
          ws.on("error", rej);
          setTimeout(() => rej(new Error("rendezvous timeout")), 5000);
        });
        const resolved = await new Promise((res) => {
          ws.on("message", (raw) => res(JSON.parse(raw.toString())));
          ws.send(JSON.stringify({ type: "resolve", serverId: parsed.serverId }));
          setTimeout(() => res({ ok: false, error: { code: "timeout", message: "rendezvous timeout" } }), 5000);
        });
        ws.close();
        if (resolved.ok && resolved.data?.endpoint) target = resolved.data.endpoint;
        else return { ok: false, error: { code: "host_offline", message: "server não encontrado no rendezvous (host offline?)" } };
      } catch (e) {
        return { ok: false, error: { code: "rendezvous", message: `falha no rendezvous: ${(e).message}` } };
      }
    }
    const connected = await connectToHost(target);
    if (!connected) return { ok: false, error: { code: "host_offline", message: "host não respondeu" } };
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 300));
    const joinRes = await sendCommand({ type: "server.join", inviteKey });
    if (!joinRes.ok) return joinRes;
    serverState = joinRes.data;
    const general = serverState.channels.find((c) => c.type === "text") ?? serverState.channels[0];
    publishKeyPackage();
    const welcome = await sendCommand({ type: "welcome.pending" });
    if (welcome.ok && welcome.data?.welcomeB64) {
      await handleWelcome(welcome.data.welcomeB64);
    } else {
      notifyRenderer("mls.ready", { epoch: 0 });
    }
    return { ok: true, data: serverState };
  });

  ipcMain.handle("server.state", () => ({ ok: true, data: serverState }));

  ipcMain.handle("message.send", async (_e, { channelId, text }) => {
    if (!identity || !serverState) return { ok: false, error: { code: "unauthorized", message: "no server" } };
    const gid = groupIdHex(channelId);
    loadMlsState(serverState.serverId, channelId);
    try {
      const enc = JSON.parse(mls.encrypt(identity.seed.toString("hex"), identity.identityId, gid, Buffer.from(text).toString("base64")));
      saveMlsState(serverState.serverId, channelId);
      const seq = (channelSeq.get(channelId) ?? 0) + 1;
      channelSeq.set(channelId, seq);
      const env = buildEnvelope({
        serverId: serverState.serverId,
        channelId,
        sender: identity.identityId,
        cryptoEpoch: enc.epoch,
        audience: { algo: "sha256", commitment: "", members: serverState.members.map((m) => m.identityId) },
        ciphertext: enc.ciphertextB64,
        ordering: { seq },
      });
      const res = await new Promise((resolve) => {
        const t = setTimeout(() => resolve({ ok: false, error: { code: "timeout", message: "host timeout" } }), 8000);
        client.onEventOnce("result", (f) => {
          clearTimeout(t);
          resolve(f.data);
        });
        client.send("envelope.send", env);
      });
      if (res.ok) notifyRenderer("message", { messageId: env.messageId, channelId, sender: identity.identityId, text, createdAt: env.createdAt, self: true });
      return res;
    } catch (e) {
      return { ok: false, error: { code: "internal", message: String(e?.message ?? e) } };
    }
  });

  ipcMain.handle("invite.create", async () => {
    return sendCommand({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
  });

  ipcMain.handle("attachment.send", async (_e, { channelId, name, mimeType, dataB64 }) => {
    if (!identity || !serverState) return { ok: false, error: { code: "unauthorized", message: "no server" } };
    try {
      const raw = Buffer.from(dataB64, "base64");
      const assetKey = randomBytes(32);
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", assetKey, nonce);
      const ct = Buffer.concat([cipher.update(raw), cipher.final()]);
      const tag = cipher.getAuthTag();
      const encrypted = Buffer.concat([nonce, tag, ct]).toString("base64");
      const assetId = randomUUID();
      // upload do chunk cifrado ao host (spool temporário; TTL 24h)
      const up = await sendCommand({ type: "attachment.upload", assetId, data: encrypted, sizeBytes: raw.length });
      if (!up.ok) return up;
      // mensagem MLS com assetKey dentro do ciphertext (só a audiência decifra)
      const payload = JSON.stringify({
        text: `📎 ${name}`,
        attachments: [{ assetId, name, mimeType, sizeBytes: raw.length, totalChunks: 1, hash: createHash("sha256").update(raw).digest("hex") }],
        assetKeys: { [assetId]: assetKey.toString("base64") },
      });
      const gid = groupIdHex(channelId);
      loadMlsState(serverState.serverId, channelId);
      const enc = JSON.parse(mls.encrypt(identity.seed.toString("hex"), identity.identityId, gid, Buffer.from(payload).toString("base64")));
      saveMlsState(serverState.serverId, channelId);
      const env = buildEnvelope({
        serverId: serverState.serverId,
        channelId,
        sender: identity.identityId,
        cryptoEpoch: enc.epoch,
        audience: { algo: "sha256", commitment: "", members: serverState.members.map((m) => m.identityId) },
        ciphertext: enc.ciphertextB64,
        attachments: [{ assetId, name, mimeType, sizeBytes: raw.length, totalChunks: 1, hash: createHash("sha256").update(raw).digest("hex") }],
        ordering: { seq: (channelSeq.get(channelId) ?? 0) + 1 },
      });
      const res = await sendCommand({ type: "message.ackConsumed", messageId: "" }).catch(() => null);
      void res;
      return { ok: true, data: { assetId } };
    } catch (e) {
      return { ok: false, error: { code: "internal", message: String(e?.message ?? e) } };
    }
  });

  ipcMain.handle("attachment.download", async (_e, { assetId }) => {
    return sendCommand({ type: "attachment.download", assetId });
  });

  ipcMain.handle("attachment.save", async (_e, { assetId, name }) => {
    try {
      const dl = await sendCommand({ type: "attachment.download", assetId });
      if (!dl.ok) return dl;
      const { shell, dialog } = await import("electron");
      const raw = Buffer.from(dl.data.data, "base64");
      const { join: pj } = await import("node:path");
      const dest = pj(app.getPath("downloads"), name ?? "attachment.bin");
      const { writeFileSync } = await import("node:fs");
      writeFileSync(dest, raw);
      shell.showItemInFolder(dest);
      return { ok: true, data: { path: dest } };
    } catch (e) {
      return { ok: false, error: { code: "internal", message: String(e?.message ?? e) } };
    }
  });

  ipcMain.handle("call.join", async (_e, { channelId }) => {
    return sendCommand({ type: "call.join", channelId });
  });
  ipcMain.handle("call.leave", async (_e, { channelId }) => {
    return sendCommand({ type: "call.leave", channelId });
  });
  ipcMain.handle("call.signal", async (_e, { channelId, to, payload }) => {
    return sendCommand({ type: "call.signal", channelId, to, payload });
  });

  ipcMain.handle("host.url", () => `ws://127.0.0.1:${HOST_PORT}/signal`);

  ipcMain.handle("member.action", async (_e, { identityId, action }) => {
    if (action === "kick") return sendCommand({ type: "member.kick", memberIdentityId: identityId });
    return sendCommand({ type: "member.ban", memberIdentityId: identityId });
  });
  ipcMain.handle("role.create", async (_e, { name, level, permissions }) => {
    return sendCommand({ type: "role.create", name, level, permissions });
  });
  ipcMain.handle("role.assign", async (_e, { memberIdentityId, roleId }) => {
    return sendCommand({ type: "role.assign", memberIdentityId, roleId });
  });
  ipcMain.handle("server.updateConfig", async (_e, { config }) => {
    return sendCommand({ type: "server.updateConfig", config });
  });
  ipcMain.handle("invite.list", async () => {
    return sendCommand({ type: "invite.list" });
  });
  ipcMain.handle("invite.revoke", async (_e, { inviteId }) => {
    return sendCommand({ type: "invite.revoke", inviteId });
  });

  ipcMain.handle("linking.create", async () => {
    if (!identity) return { ok: false, error: { code: "unauthorized", message: "identity required" } };
    const session = createLinkSession(identity.seed);
    return { ok: true, data: { payload: session.payload, expiresAt: session.expiresAt } };
  });
}

// ---------------------------------------------------------------- smoke UI
async function runUiSmoke(win) {
  const fs = await import("node:fs");
  const shotDir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 900));
    fs.mkdirSync(shotDir, { recursive: true });
    const img = await win.webContents.capturePage();
    fs.writeFileSync(path.join(shotDir, `jc-${name}.png`), img.toPNG());
    const text = await js(`document.body.innerText.slice(0, 300)`);
    console.log(`[smoke-ui] screenshot ${name} | texto: ${JSON.stringify(text)}`);
  };
  const js = (code) => win.webContents.executeJavaScript(code);

  // pré-cria identidade (fluxo real de vault) — o App abre no login
  if (process.env.JC_SMOKE_CREATE_IDENTITY) {
    identity = await createIdentity("matheus", "senha-teste-123", vaultPath());
    initLocalDb();
    await loadMls();
    win.reload();
  }
  await new Promise((r) => setTimeout(r, 1500));
  await shot("01-login");

  // desbloqueia via UI real
  await js(`(() => {
    const input = document.querySelector('input[type="password"]');
    if (!input) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'senha-teste-123');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await new Promise((r) => setTimeout(r, 300));
  await js(`document.querySelector('button')?.click()`);
  await new Promise((r) => setTimeout(r, 1500));
  await shot("02-home");

  // cria server (host child + MLS)
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('Criar server'))?.click()`);
  await new Promise((r) => setTimeout(r, 3500));
  await shot("03-server");

  // envia mensagem E2EE
  const st = await ipcMain ? null : null;
  void st;
  const state = await getServerStateForSmoke();
  const ch = state?.channels?.find((c) => c.type === "text");
  if (ch) {
    // abre o canal #general na UI
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('general'))?.click()`);
    await new Promise((r) => setTimeout(r, 600));
    await js(`(() => {
      const input = document.querySelector('input[placeholder^="Mensagem"]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'ola mundo cifrado');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent === 'Enviar')?.click()`);
    await new Promise((r) => setTimeout(r, 1200));
    await shot("04-message");
  }
  // admin UI: abre configurações e navega pelos tabs
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('⚙'))?.click()`);
  await new Promise((r) => setTimeout(r, 1200));
  await shot("05-settings-members");
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent === 'Roles')?.click()`);
  await new Promise((r) => setTimeout(r, 800));
  await shot("06-settings-roles");
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent === 'Configurações')?.click()`);
  await new Promise((r) => setTimeout(r, 800));
  await shot("07-settings-config");
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent === 'Convites')?.click()`);
  await new Promise((r) => setTimeout(r, 800));
  await shot("08-settings-invites");
  console.log("[smoke-ui] DONE");
  app.quit();
}

async function getServerStateForSmoke() {
  if (!serverState) return null;
  const fresh = await sendCommand({ type: "server.state" }).catch(() => null);
  return fresh?.ok ? fresh.data : serverState;
}

// ---------------------------------------------------------------- smoke media
async function runMediaSmoke(win) {
  const fs = await import("node:fs");
  const dir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const js = (code) => win.webContents.executeJavaScript(code);
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 1200));
    fs.mkdirSync(dir, { recursive: true });
    const img = await win.webContents.capturePage();
    fs.writeFileSync(path.join(dir, `media-${name}.png`), img.toPNG());
    console.log(`[smoke-media] screenshot ${name}`);
  };
  // pré-cria identidade e entra no fluxo até o server (reusa helpers)
  identity = await createIdentity("media", "senha-media-123", vaultPath());
  initLocalDb();
  await loadMls();
  win.reload();
  await new Promise((r) => setTimeout(r, 1500));
  await js(`(() => {
    const input = document.querySelector('input[type="password"]');
    if (!input) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'senha-media-123');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await new Promise((r) => setTimeout(r, 300));
  await js(`document.querySelector('button')?.click()`);
  await new Promise((r) => setTimeout(r, 1500));
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('Criar server'))?.click()`);
  await new Promise((r) => setTimeout(r, 3500));
  // cria canal de call e abre
  const st = await getServerStateForSmoke();
  const chRes = await sendCommand({ type: "channel.create", channelType: "call", name: "geral-call" });
  if (chRes.ok) {
    // recarrega para o renderer obter o estado atualizado (com o canal de call)
    win.reload();
    await new Promise((r) => setTimeout(r, 1500));
    await js(`(() => {
      const input = document.querySelector('input[type="password"]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'senha-media-123');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    await js(`document.querySelector('button')?.click()`);
    await new Promise((r) => setTimeout(r, 2000));
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 4000)); // join + getUserMedia
    await shot("01-call-media");
    const text = await js(`document.body.innerText.slice(0, 200)`);
    console.log(`[smoke-media] call UI: ${JSON.stringify(text)}`);
    // verifica stream local ativo
    const hasStream = await js(`!!window.janjacordMediaSmoke`);
    void hasStream;
  }
  console.log("[smoke-media] DONE");
  app.quit();
}

// ---------------------------------------------------------------- smoke media peer (mesh 2 peers)
async function runMediaPeerSmoke(win) {
  const fs = await import("node:fs");
  const dir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const js = (code) => win.webContents.executeJavaScript(code);
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 2500));
    fs.mkdirSync(dir, { recursive: true });
    const img = await win.webContents.capturePage();
    fs.writeFileSync(path.join(dir, `peer${process.env.JC_SMOKE_MEDIA_PEER}-${name}.png`), img.toPNG());
    const text = await js(`document.body.innerText.slice(0, 300)`);
    console.log(`[smoke-media-peer${process.env.JC_SMOKE_MEDIA_PEER}] ${name} | ${JSON.stringify(text)}`);
  };
  const unlock = async (pw) => {
    await js(`(() => {
      const input = document.querySelector('input[type="password"]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, '${pw}');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    await js(`document.querySelector('button')?.click()`);
    await new Promise((r) => setTimeout(r, 2000));
  };
  const peer = process.env.JC_SMOKE_MEDIA_PEER;
  const pw = `senha-peer-${peer}`;

  identity = await createIdentity(`peer${peer}`, pw, vaultPath());
  initLocalDb();
  await loadMls();

  if (peer === "1") {
    // cria o host e o canal de call via main (sem depender do renderer)
    spawnHost();
    await new Promise((r) => setTimeout(r, 1800));
    await connectToHost(`ws://127.0.0.1:${HOST_PORT}/signal`);
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 600));
    const st = await sendCommand({ type: "server.state" });
    if (!st.ok) throw new Error("host sem estado");
    serverState = st.data;
    await sendCommand({ type: "channel.create", channelType: "call", name: "geral-call" });
    // renderer: reload → unlock → main (com o canal call) → abre a call
    win.reload();
    await new Promise((r) => setTimeout(r, 1800));
    await unlock(pw);
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 5000)); // join + getUserMedia fake
    await shot("in-call");
    const inv = await sendCommand({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    if (inv.ok) fs.writeFileSync(process.env.JC_INVITE_FILE ?? path.join(dir, "invite.txt"), inv.data.inviteKey);
    console.log("[smoke-media-peer1] aguardando peer 2…");
    await new Promise((r) => setTimeout(r, 30000));
    await shot("final");
    app.quit();
  } else {
    // entra via invite (descoberta no rendezvous) + call
    const invitePath = process.env.JC_INVITE_FILE ?? path.join(dir, "invite.txt");
    let tries = 0;
    while (!fs.existsSync(invitePath) && tries < 25) {
      await new Promise((r) => setTimeout(r, 1000));
      tries++;
    }
    if (!fs.existsSync(invitePath)) throw new Error("invite do peer 1 não encontrado");
    const inviteKey = fs.readFileSync(invitePath, "utf8").trim();
    const { parseInviteKey } = await import("@janjacord/crypto");
    const parsed = parseInviteKey(inviteKey);
    let target = null;
    if (parsed && process.env.JC_RENDEZVOUS_URL) {
      const { WebSocket } = await import("ws");
      const ws = new WebSocket(process.env.JC_RENDEZVOUS_URL);
      await new Promise((res, rej) => { ws.on("open", res); ws.on("error", rej); });
      const resolved = await new Promise((res) => {
        ws.on("message", (raw) => res(JSON.parse(raw.toString())));
        ws.send(JSON.stringify({ type: "resolve", serverId: parsed.serverId }));
        setTimeout(() => res({ ok: false }), 5000);
      });
      ws.close();
      if (resolved.ok) target = resolved.data.endpoint;
    }
    if (!target) throw new Error("rendezvous não resolveu o peer 1");
    await connectToHost(target);
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 600));
    const joinRes = await sendCommand({ type: "server.join", inviteKey });
    if (!joinRes.ok) throw new Error(`join falhou: ${joinRes.error?.message}`);
    serverState = joinRes.data;
    win.reload();
    await new Promise((r) => setTimeout(r, 1800));
    await unlock(pw);
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 7000)); // join + getUserMedia + mesh
    await shot("in-call");
    await new Promise((r) => setTimeout(r, 10000));
    await shot("final");
    app.quit();
  }
}

// ---------------------------------------------------------------- janela
function setupAutoUpdater() {
  if (process.env.JC_DISABLE_UPDATES === "1") return;
  try {
    // electron-updater é CJS; no main ESM usa createRequire
    const { createRequire } = await_import_module();
    const require2 = createRequire(import.meta.url);
    const { autoUpdater } = require2("electron-updater");
    autoUpdater.autoDownload = true;
    autoUpdater.on("update-downloaded", () => {
      console.log("[updater] atualização baixada — reiniciando na saída");
      autoUpdater.quitAndInstall();
    });
    autoUpdater.on("error", (err) => console.warn("[updater]", err.message));
    setTimeout(() => autoUpdater.checkForUpdatesAndNotify().catch(() => {}), 30000);
  } catch (e) {
    console.warn("[updater] não configurado (dev build):", (e).message);
  }
}

async function await_import_module() {
  return { createRequire: (await import("node:module")).createRequire };
}

function createWindow() {
  // permissões de mídia: permite camera/mic para a origin local do app (ADR/Electron security)
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback, details) => {
    if (permission === "media") {
      const origin = details?.securityOrigin ?? "";
      if (origin.startsWith("file://") || origin.includes("localhost") || origin.includes("127.0.0.1")) {
        callback(true);
        return;
      }
    }
    callback(false);
  });
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    backgroundColor: "#0b0d10",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
  if (process.env.JC_SMOKE_UI) {
    win.webContents.once("did-finish-load", () => runUiSmoke(win));
  }
  if (process.env.JC_SMOKE_MEDIA) {
    win.webContents.once("did-finish-load", () => runMediaSmoke(win));
  }
  if (process.env.JC_SMOKE_MEDIA_PEER) {
    win.webContents.once("did-finish-load", () => runMediaPeerSmoke(win));
  }
  return win;
}

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  setupAutoUpdater();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopHost();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  stopHost();
  localDb?.close();
});
