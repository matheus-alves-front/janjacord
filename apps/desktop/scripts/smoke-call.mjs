/**
 * Smoke de call (WebRTC mesh): 2 peers conectam via signaling relé pelo host
 * (call.join/call.signal) e estabelecem DataChannel P2P real (node-datachannel).
 * A mídia (mic/camera) requer hardware — o transporte/sinalização é validado aqui.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";
import nodeDataChannel from "node-datachannel";

const __dirname = dirname(fileURLToPath(import.meta.url));
const HOST_PORT = 8934;
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

function waitFor(ws, event, t = 8000) {
  return new Promise((res, rej) => {
    const tm = setTimeout(() => rej(new Error(`timeout ${event}`)), t);
    ws.on("message", function h(raw) {
      const f = JSON.parse(raw.toString());
      if (f.event === event) {
        clearTimeout(tm);
        ws.off("message", h);
        res(f.data);
      }
    });
  });
}

async function connect(identityId, url) {
  const client = new HostClient(url, { identityId });
  await new Promise((res) => {
    client.onOpen(() => res());
    setTimeout(res, 5000);
  });
  // listener registrado ANTES do hello (resposta síncrona do host)
  const helloPromise = new Promise((res) => {
    client.onEventOnce("result", (f) => res(f.data));
    setTimeout(() => res(null), 8000);
  });
  client.send("hello", { identityId });
  const hello = await helloPromise;
  if (hello?.ok) return { client, state: hello }; // envelope {ok, data}
  return { client, state: null };
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-call-"));
  let host = null;
  try {
    const aliceId = "alice-call";
    const bobId = "bob-call";
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "a-vault.json"));
    const bob = await createIdentity("bob", "senha-bob-456", join(dir, "b-vault.json"));

    host = fork(JANJANODE_MAIN, [], {
      env: {
        ...process.env,
        JC_DB_KEY: alice.dbKey.toString("hex"),
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: aliceId,
        JC_OWNER_NICKNAME: "alice",
        JC_SERVER_NAME: "CallTest",
        JC_PORT: String(HOST_PORT),
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    host.stdout?.on("data", (d) => process.stdout.write(d));
    host.stderr?.on("data", (d) => process.stderr.write(d));
    await new Promise((r) => setTimeout(r, 2000));

    const a = await connect(aliceId, `ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(a.state?.ok, "alice conecta");
    // cria canal de call
    const chRes = await a.client.request({ type: "channel.create", channelType: "call", name: "geral-call" });
    assert(chRes.ok, "owner cria canal de call");
    const callCh = chRes.data;

    // bob entra por invite
    const inv = await a.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    const b = await connect(bobId, `ws://127.0.0.1:${HOST_PORT}/signal`);
    const joinRes = await b.client.request({ type: "server.join", inviteKey: inv.data.inviteKey });
    assert(joinRes.ok, "bob entra no server");

    // ambos entram na call
    const joinA = await a.client.request({ type: "call.join", channelId: callCh.id });
    const joinB = await b.client.request({ type: "call.join", channelId: callCh.id });
    assert(joinA.ok && joinB.ok, "ambos entram na call (join_call)");
    assert(joinB.data.participants.includes(aliceId), "bob vê alice na call");

    // WebRTC mesh via node-datachannel com signaling relé pelo host
    console.log("[smoke-call] estabelecendo DataChannel P2P via signaling do host…");
    const pcA = new nodeDataChannel.PeerConnection("alice-pc", { iceServers: [] });
    const pcB = new nodeDataChannel.PeerConnection("bob-pc", { iceServers: [] });

    // relé: alice -> host -> bob, e vice-versa
    const bSignalPromise = new Promise((resolve) => {
      b.client.onEvent((evt) => {
        if (evt.type === "call.signal" && evt.from === aliceId) resolve(evt.payload);
      });
    });
    pcA.onLocalDescription((sdp, type) => {
      console.log("[dbg] alice envia offer/answer", type);
      a.client.send("command", { type: "call.signal", channelId: callCh.id, to: bobId, payload: { type: type.toLowerCase(), sdp } });
    });
    pcA.onLocalCandidate((candidate, mid) => {
      a.client.send("command", { type: "call.signal", channelId: callCh.id, to: bobId, payload: { type: "candidate", candidate: JSON.stringify({ candidate, mid }) } });
    });
    pcB.onLocalDescription((sdp, type) => {
      b.client.send("command", { type: "call.signal", channelId: callCh.id, to: aliceId, payload: { type: type.toLowerCase(), sdp } });
    });
    pcB.onLocalCandidate((candidate, mid) => {
      b.client.send("command", { type: "call.signal", channelId: callCh.id, to: aliceId, payload: { type: "candidate", candidate: JSON.stringify({ candidate, mid }) } });
    });

    // logs de signaling
    a.client.onEvent((evt) => { if (evt.type === "call.signal") console.log("[dbg] alice recebe", evt.payload?.type); });
    b.client.onEvent((evt) => { if (evt.type === "call.signal") console.log("[dbg] bob recebe", evt.payload?.type); });

    // alice envia offer (chamador)
    const dcA = pcA.createDataChannel("voice");
    dcA.onOpen(() => {
      console.log("[dbg] DC aberto, enviando mensagem");
      dcA.sendMessage("ola via mesh");
    });
    let got = "";
    const gotPromise = new Promise((resolve) => {
      pcB.onDataChannel((dc) => {
        dc.onMessage((msg) => {
          got = msg.toString();
          resolve();
        });
      });
    });

    // bob processa signaling recebido
    b.client.onEvent(async (evt) => {
      if (evt.type === "call.signal") console.log("[dbg] bob RECEBE", evt.payload?.type);
      if (evt.type !== "call.signal" || evt.from !== aliceId) return;
      const p = evt.payload;
      if (p.type === "offer") pcB.setRemoteDescription(p.sdp, "Offer");
      if (p.type === "candidate") {
        const c = JSON.parse(p.candidate);
        pcB.addRemoteCandidate(c.candidate, c.mid);
      }
    });
    a.client.onEvent(async (evt) => {
      if (evt.type !== "call.signal" || evt.from !== bobId) return;
      const p = evt.payload;
      if (p.type === "answer") pcA.setRemoteDescription(p.sdp, "Answer");
      if (p.type === "candidate") {
        const c = JSON.parse(p.candidate);
        pcA.addRemoteCandidate(c.candidate, c.mid);
      }
    });

    pcA.onStateChange((s) => console.log("[dbg] alice pc state:", s));
    pcB.onStateChange((s) => console.log("[dbg] bob pc state:", s));

    // inicia negociação
    pcA.setLocalDescription("", "Offer");
    await gotPromise;
    assert(got === "ola via mesh", `DataChannel P2P via host: "${got}"`);
    dcA.close();
    pcA.close();
    pcB.close();

    // limite de participantes (guardrail)
    const inv2 = await a.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    const carol = await connect("carol-call", `ws://127.0.0.1:${HOST_PORT}/signal`);
    await carol.client.request({ type: "server.join", inviteKey: inv2.data.inviteKey });
    const joinC = await carol.client.request({ type: "call.join", channelId: callCh.id });
    assert(joinC.ok, "carol entra na call");

    // member sem join_call (role member tem join_call default — ok); testa canal text como call
    const textCh = a.state.data.channels.find((c) => c.type === "text");
    const badJoin = await carol.client.request({ type: "call.join", channelId: textCh.id });
    assert(!badJoin.ok && badJoin.error.code === "not_found", "join em canal de texto rejeitado (not_found)");

    if (failures === 0) console.log("[smoke-call] MESH + SIGNALING OK");
    else console.error(`[smoke-call] ${failures} falhas`);
  } finally {
    host?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-call] erro:", e);
  process.exit(1);
});
