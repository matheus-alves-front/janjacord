import { describe, it, expect, beforeAll } from "vitest";
import * as mls from "@janjacord/crypto-core";

const seedA = "a".repeat(64);
const seedB = "b".repeat(64);
const gid = Buffer.from("group-1").toString("hex");

beforeAll(async () => {
  await mls.default;
});

describe("crypto-core MLS (wasm)", () => {
  it("fluxo completo: create -> add -> join -> encrypt/decrypt -> remove", () => {
    const created = JSON.parse(mls.create_group(seedA, "alice", gid));
    expect(created.epoch).toBe(0);

    const kp = mls.generate_key_package(seedB, "bob");
    expect(kp.length).toBeGreaterThan(100);

    const added = JSON.parse(mls.add_member(seedA, "alice", gid, kp));
    expect(added.commitB64.length).toBeGreaterThan(100);
    expect(added.welcomeB64.length).toBeGreaterThan(100);

    const joined = JSON.parse(mls.join_group(seedB, "bob", added.welcomeB64));
    expect(joined.epoch).toBe(1);

    const msg = JSON.parse(mls.encrypt(seedA, "alice", gid, Buffer.from("ola janjacord").toString("base64")));
    const dec = JSON.parse(mls.decrypt(seedB, "bob", gid, msg.ciphertextB64));
    expect(Buffer.from(dec.plaintextB64, "base64").toString()).toBe("ola janjacord");
    expect(dec.senderIndex).toBe(0);

    // persistência: export -> import mantém estado
    const exported = mls.export_group("alice", gid);
    expect(exported.length).toBeGreaterThan(500);
    mls.import_group("alice", gid, exported);
    const dec2 = JSON.parse(mls.decrypt(seedB, "bob", gid, msg.ciphertextB64));
    expect(Buffer.from(dec2.plaintextB64, "base64").toString()).toBe("ola janjacord");

    // remove member (leaf 1 = bob)
    const removed = JSON.parse(mls.remove_member(seedA, "alice", gid, 1));
    expect(removed.commitB64.length).toBeGreaterThan(100);
  });

  it("processa commit do outro lado (epoch avança para todos)", () => {
    // recria grupo limpo
    const gid2 = Buffer.from("group-2").toString("hex");
    mls.create_group(seedA, "alice", gid2);
    const kp = mls.generate_key_package(seedB, "bob");
    const added = JSON.parse(mls.add_member(seedA, "alice", gid2, kp));
    mls.join_group(seedB, "bob", added.welcomeB64);
    // bob processa o commit que adicionou ele? bob já entrou via welcome (estado atual)
    // agora alice remove bob e bob processa o commit
    const removed = JSON.parse(mls.remove_member(seedA, "alice", gid2, 1));
    mls.process_commit(seedB, "bob", gid2, removed.commitB64);
    // bob não deve mais decifrar mensagens novas
    const msg = JSON.parse(mls.encrypt(seedA, "alice", gid2, Buffer.from("secreto").toString("base64")));
    expect(() => mls.decrypt(seedB, "bob", gid2, msg.ciphertextB64)).toThrow();
  });
});
