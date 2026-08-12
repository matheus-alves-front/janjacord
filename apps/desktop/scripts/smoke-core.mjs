/**
 * Smoke do core desktop (fluxo M1): 2 identidades reais, JanjaNode child, MLS E2EE,
 * entrega, consumo e purge. Roda sem display (sem Electron) — valida a lógica que o
 * main do Electron executa (vault + crypto-core + HostClient + protocolo).
 */
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createHmac } from "node:crypto";
import { createIdentity, generateRecoveryKey } from "@janjacord/identity";
import { ed25519PublicKey } from "@janjacord/crypto";
import { EncryptedDatabase } from "@janjacord/persistence";
import { HostClient } from "@janjacord/networking";
import { attachmentSha256, buildEnvelope, decodeAttachmentChunk, encodeAttachmentChunks } from "@janjacord/protocol";
import * as mls from "@janjacord/crypto-core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const HOST_PORT = 8933;
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

class DesktopInstance {
  constructor(label) {
    this.label = label;
    this.identity = null;
    this.db = null;
    this.client = null;
    this.serverState = null;
  }

  async create(nickname, password, dir) {
    this.identity = await createIdentity(nickname, password, join(dir, "vault.json"));
    this.db = new EncryptedDatabase(join(dir, "local.db"), this.identity.dbKey);
    this.db.migrate(
      "CREATE TABLE IF NOT EXISTS mls_groups (key TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at INTEGER NOT NULL);",
    );
    await mls.default;
  }

  gid(channelId) {
    return Buffer.from(channelId.replace(/-/g, ""), "hex").toString("hex");
  }

  saveMls(serverId, channelId) {
    const state = mls.export_group(this.identity.identityId, this.gid(channelId));
    this.db.raw
      .prepare("INSERT INTO mls_groups (key, state, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at")
      .run(`mls:${serverId}:${channelId}`, state, Date.now());
  }

  loadMls(serverId, channelId) {
    const row = this.db.raw.prepare("SELECT state FROM mls_groups WHERE key = ?").get(`mls:${serverId}:${channelId}`);
    if (!row) return false;
    mls.import_group(this.identity.identityId, this.gid(channelId), row.state);
    return true;
  }

  async connect(url) {
    this.client = new HostClient(url, { identityId: this.identity.identityId });
    await new Promise((res) => {
      this.client.onOpen(() => res());
      setTimeout(res, 5000);
    });
    this.client.send("hello", { identityId: this.identity.identityId });
    return this.waitResult(8000);
  }

  command(cmd) {
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve({ ok: false, error: { code: "timeout", message: "host timeout" } }), 8000);
      this.client.onEventOnce("result", (f) => {
        clearTimeout(t);
        resolve(f.data);
      });
      this.client.command(cmd);
    });
  }

  commandWithoutWaiting(cmd) {
    this.client.command(cmd);
  }

  async disconnect() {
    if (!this.client) return;
    const active = this.client;
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 1_000);
      active.onClose(() => {
        clearTimeout(timer);
        resolve();
      });
      active.close();
    });
    if (this.client === active) this.client = null;
  }

  waitResult(ms = 8000) {
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(null), ms);
      this.client.onEventOnce("result", (f) => {
        clearTimeout(t);
        resolve(f.data);
      });
    });
  }

  waitEvent(ms = 8000) {
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(null), ms);
      this.client.onEventOnce("event", (f) => {
        clearTimeout(t);
        resolve(f.data);
      });
    });
  }

  publishKeyPackage() {
    const kp = mls.generate_key_package(this.identity.seed.toString("hex"), this.identity.identityId);
    return this.command({ type: "keypackage.upload", keyPackageB64: kp });
  }

  ensureGroup(serverId, channelId) {
    if (this.loadMls(serverId, channelId)) return;
    mls.create_group(this.identity.seed.toString("hex"), this.identity.identityId, this.gid(channelId));
    this.saveMls(serverId, channelId);
  }

  sendText(channelId, text) {
    const enc = JSON.parse(mls.encrypt(this.identity.seed.toString("hex"), this.identity.identityId, this.gid(channelId), Buffer.from(text).toString("base64")));
    this.saveMls(this.serverState.serverId, channelId);
    const env = buildEnvelope({
      serverId: this.serverState.serverId,
      channelId,
      sender: this.identity.identityId,
      cryptoEpoch: enc.epoch,
      audience: { algo: "sha256", commitment: "", members: this.serverState.members.map((m) => m.identityId) },
      ciphertext: enc.ciphertextB64,
      ordering: { seq: 1 },
    });
    return this.command({ type: "message.send", envelope: env });
  }

  decrypt(env) {
    this.loadMls(this.serverState.serverId, env.channelId);
    const dec = JSON.parse(mls.decrypt(this.identity.seed.toString("hex"), this.identity.identityId, this.gid(env.channelId), env.ciphertext));
    return Buffer.from(dec.plaintextB64, "base64").toString("utf8");
  }
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-desktop-"));
  const hostDir = join(dir, "host");
  let host = null;
  try {
    console.log("[smoke-core] criando identidades…");
    const alice = new DesktopInstance("alice");
    const bob = new DesktopInstance("bob");
    await alice.create("alice", "senha-alice-123", join(dir, "a"));
    await bob.create("bob", "senha-bob-456", join(dir, "b"));
    assert(alice.identity.identityId !== bob.identity.identityId, "identidades distintas");
    assert(generateRecoveryKey(alice.identity.seed).length > 60, "recovery key gerada");

    console.log("[smoke-core] subindo host (janjanode child)…");
    const authoritySeed = createHmac("sha256", alice.identity.seed).update("smoke-authority").digest();
    const hostSeed = createHmac("sha256", alice.identity.seed).update("smoke-host").digest();
    host = fork(JANJANODE_MAIN, [], {
      env: {
        ...process.env,
        JC_DB_KEY: alice.identity.dbKey.toString("hex"),
        JC_DB_PATH: join(hostDir, "server.db"),
        JC_OWNER_IDENTITY: alice.identity.identityId,
        JC_OWNER_NICKNAME: "alice",
        JC_OWNER_PUBLIC_KEY: ed25519PublicKey(alice.identity.seed).toString("base64url"),
        JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
        JC_HOST_SIGNING_SEED: hostSeed.toString("hex"),
        JC_ALLOW_LEGACY_AUTH: "1",
        JC_SERVER_NAME: "Teste",
        JC_PORT: String(HOST_PORT),
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    });
    host.stdout?.on("data", (d) => console.log("[host]", d.toString().trim()));
    host.stderr?.on("data", (d) => console.error("[host-err]", d.toString().trim()));
    host.on("exit", (c) => console.log(`[host] exit ${c}`));
    await new Promise((r) => setTimeout(r, 2500));

    console.log("[smoke-core] alice conecta e cria server…");
    const aliceHello = await alice.connect(`ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(aliceHello?.ok, "alice hello + estado");
    alice.serverState = aliceHello.data;
    const general = alice.serverState.channels.find((c) => c.type === "text");
    alice.ensureGroup(alice.serverState.serverId, general.id);
    await alice.publishKeyPackage();

    console.log("[smoke-core] alice cria invite…");
    const inv = await alice.command({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    assert(inv.ok && /^JC[12]-/.test(inv.data.inviteKey), "invite JC1/JC2-… criado");

    console.log("[smoke-core] bob conecta e entra…");
    const bobHello = await bob.connect(`ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(bobHello?.ok === false, "bob hello (ainda não é membro)");
    const joinRes = await bob.command({ type: "server.join", inviteKey: inv.data.inviteKey });
    assert(joinRes.ok, "bob entra por invite");
    bob.serverState = joinRes.data;
    await bob.publishKeyPackage();
    // alice atualiza o estado (bob agora é membro)
    const stateA = await alice.command({ type: "server.state" });
    alice.serverState = stateA.data;

    console.log("[smoke-core] alice adiciona bob ao grupo MLS…");
    const kpBob = await alice.command({ type: "keypackage.get", targetIdentityId: bob.identity.identityId });
    assert(kpBob.ok, "alice obtém key package do bob");
    const added = JSON.parse(mls.add_member(alice.identity.seed.toString("hex"), alice.identity.identityId, alice.gid(general.id), kpBob.data.keyPackageB64));
    alice.saveMls(alice.serverState.serverId, general.id);
    await bob.disconnect();
    const welcomePush = await alice.command({ type: "welcome.push", targetIdentityId: bob.identity.identityId, welcomeB64: added.welcomeB64 });
    assert(welcomePush.ok, "welcome persistido enquanto bob está desconectado");

    console.log("[smoke-core] bob reconecta, recupera Welcome e perde somente a resposta do ACK…");
    const bobReconnect = await bob.connect(`ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(bobReconnect?.ok, "bob reautentica após desconexão");
    const welcomePending = await bob.command({ type: "welcome.pending" });
    assert(welcomePending.ok && welcomePending.data?.welcomeId, "bob consulta Welcome pendente após reconectar");
    const joined = JSON.parse(mls.join_group(bob.identity.seed.toString("hex"), bob.identity.identityId, welcomePending.data.welcomeB64));
    bob.saveMls(bob.serverState.serverId, general.id);
    assert(joined.epoch >= 1, "bob entra no grupo (epoch ≥ 1)");
    bob.commandWithoutWaiting({ type: "welcome.ackConsumed", welcomeId: welcomePending.data.welcomeId });
    await new Promise((resolve) => setTimeout(resolve, 100));
    await bob.disconnect();
    const bobAfterLostAckResponse = await bob.connect(`ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(bobAfterLostAckResponse?.ok, "bob reautentica depois de perder a resposta do ACK");
    const welcomeAfterAck = await bob.command({ type: "welcome.pending" });
    assert(welcomeAfterAck.ok && welcomeAfterAck.data === null, "ACK de Welcome é idempotente quando a resposta se perde");

    console.log("[smoke-core] E2EE real: bob → alice…");
    const bobDeliverPromise = alice.waitEvent();
    const sent = await bob.sendText(general.id, "ola alice, mensagem cifrada");
    assert(sent.ok, "bob envia envelope");
    const deliver = await bobDeliverPromise;
    assert(deliver?.type === "envelope.deliver", "alice recebe envelope");
    const plain = alice.decrypt(deliver.envelope);
    assert(plain === "ola alice, mensagem cifrada", `alice decifra E2EE: "${plain}"`);

    // purge: só ocorre quando TODOS os elegíveis consomem (ADR-004)
    await alice.command({ type: "message.ackConsumed", messageId: deliver.envelope.messageId });
    await bob.command({ type: "message.ackConsumed", messageId: deliver.envelope.messageId });
    const pendA = await alice.command({ type: "message.getPending" });
    assert(!pendA.data.some((m) => m.messageId === deliver.envelope.messageId), "purge após todos consumirem");

    console.log("[smoke-core] E2EE reverso chega via message.getPending após desconexão…");
    await bob.disconnect();
    const sent2 = await alice.sendText(general.id, "oi bob, criptografia real");
    assert(sent2.ok, "alice envia envelope enquanto bob está desconectado");
    const bobMessageReconnect = await bob.connect(`ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(bobMessageReconnect?.ok, "bob reautentica para recuperar mensagens");
    const pendingForBob = await bob.command({ type: "message.getPending" });
    const deliver2 = pendingForBob.data.find((envelope) => envelope.channelId === general.id && envelope.sender === alice.identity.identityId);
    assert(Boolean(deliver2), "mensagem enviada durante desconexão aparece em message.getPending");
    const plain2 = bob.decrypt(deliver2);
    assert(plain2 === "oi bob, criptografia real", `bob decifra E2EE: "${plain2}"`);

    // consome a segunda mensagem também (purge completo)
    await alice.command({ type: "message.ackConsumed", messageId: deliver2.messageId });
    await bob.command({ type: "message.ackConsumed", messageId: deliver2.messageId });
    await new Promise((r) => setTimeout(r, 200));

    console.log("[smoke-core] attachment E2EE (imagem)…");
    // alice cifra um "arquivo" (asset key fora do host)
    const assetKey = Buffer.alloc(32, 9);
    const fakeImg = Buffer.concat([
      Buffer.from("PNG-DADOS-FICTICIOS-1234567890"),
      Buffer.alloc(70 * 1024, 0x5a),
    ]);
    const nonceA = Buffer.alloc(12, 1);
    const { createCipheriv } = await import("node:crypto");
    const cip = createCipheriv("aes-256-gcm", assetKey, nonceA);
    const ctA = Buffer.concat([cip.update(fakeImg), cip.final()]);
    const tagA = cip.getAuthTag();
    const encA = Buffer.concat([nonceA, tagA, ctA]);
    const transportChunks = encodeAttachmentChunks(encA);
    const assetId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const attachmentAudience = bob.serverState.members.map((m) => m.identityId);
    const begun = await bob.command({
      type: "attachment.upload.begin", assetId, channelId: general.id,
      audienceMembers: attachmentAudience, sizeBytes: encA.length,
      totalChunks: transportChunks.length, hash: attachmentSha256(encA),
    });
    assert(begun.ok, "reserva agregada do attachment cifrado no host");
    for (const chunk of transportChunks) {
      const up = await bob.command({ type: "attachment.upload.chunk", assetId, ...chunk });
      assert(up.ok, `upload do chunk cifrado ${chunk.index + 1}/${transportChunks.length}`);
    }
    const completed = await bob.command({ type: "attachment.upload.complete", assetId });
    assert(completed.ok, "upload cifrado completo e íntegro no host");
    // mensagem MLS com payload {text, attachments, assetKeys}
    const payload = JSON.stringify({
      text: "📎 foto.png",
      attachments: [{ assetId, name: "foto.png", mimeType: "image/png", sizeBytes: fakeImg.length, totalChunks: transportChunks.length, hash: attachmentSha256(fakeImg) }],
      assetKeys: { [assetId]: assetKey.toString("base64") },
    });
    const encMsg = JSON.parse(mls.encrypt(bob.identity.seed.toString("hex"), bob.identity.identityId, bob.gid(general.id), Buffer.from(payload).toString("base64")));
    bob.saveMls(bob.serverState.serverId, general.id);
    const envA = buildEnvelope({
      serverId: bob.serverState.serverId,
      channelId: general.id,
      sender: bob.identity.identityId,
      cryptoEpoch: encMsg.epoch,
      audience: { algo: "sha256", commitment: "", members: attachmentAudience },
      ciphertext: encMsg.ciphertextB64,
      attachments: [{ assetId, name: "foto.png", mimeType: "image/png", sizeBytes: fakeImg.length, totalChunks: transportChunks.length, hash: attachmentSha256(fakeImg) }],
      ordering: { seq: 1 },
    });
    const aliceAttachPromise = alice.waitEvent();
    const attachmentSent = await bob.command({ type: "message.send", envelope: envA });
    assert(attachmentSent.ok, "envelope do attachment é persistido transacionalmente");
    const deliverA = (await aliceAttachPromise);
    const payloadDec = JSON.parse(alice.decrypt(deliverA.envelope));
    assert(payloadDec.assetKeys?.[assetId] === assetKey.toString("base64"), "asset key viaja no ciphertext MLS (host não vê)");
    const dl = await alice.command({ type: "attachment.download", assetId });
    assert(dl.ok, "download do manifesto cifrado");
    const downloadedChunks = [];
    for (let index = 0; index < dl.data.totalChunks; index += 1) {
      const part = await alice.command({ type: "attachment.download.chunk", assetId, index });
      assert(part.ok, `download do chunk cifrado ${index + 1}/${dl.data.totalChunks}`);
      downloadedChunks.push(decodeAttachmentChunk(part.data.data, part.data.sizeBytes, part.data.hash));
    }
    const encB = Buffer.concat(downloadedChunks, dl.data.sizeBytes);
    const dNonce = encB.subarray(0, 12);
    const dTag = encB.subarray(12, 28);
    const dCt = encB.subarray(28);
    const { createDecipheriv } = await import("node:crypto");
    const decip = createDecipheriv("aes-256-gcm", assetKey, dNonce);
    decip.setAuthTag(dTag);
    const recovered = Buffer.concat([decip.update(dCt), decip.final()]);
    assert(recovered.equals(fakeImg), "alice decifra o attachment (bytes íntegros)");
    // consome a mensagem do attachment (purge completo)
    await alice.command({ type: "message.ackConsumed", messageId: deliverA.envelope.messageId });
    await bob.command({ type: "message.ackConsumed", messageId: deliverA.envelope.messageId });
    await new Promise((r) => setTimeout(r, 200));

    // verificação de privacidade: nenhum plaintext no storage do host (ADR-004/016)
    const hostDb = new EncryptedDatabase(join(hostDir, "server.db"), alice.identity.dbKey);
    const spoolRows = hostDb.raw.prepare("SELECT envelope, recipients FROM spool").all();
    const allHostData = JSON.stringify(spoolRows);
    const noPlaintext = !allHostData.includes("ola alice, mensagem cifrada") && !allHostData.includes("oi bob, criptografia real");
    assert(noPlaintext, "nenhum plaintext no storage do host (spool só tem ciphertext)");
    assert(spoolRows.length === 0, "spool do host vazio após purge (nenhum resíduo)");
    hostDb.close();

    if (failures === 0) console.log("[smoke-core] FLUXO M1 E2EE REAL OK — SEM PLAINTEXT NO HOST");
    else console.error(`[smoke-core] ${failures} falhas`);
  } finally {
    host?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-core] erro:", e);
  process.exit(1);
});
