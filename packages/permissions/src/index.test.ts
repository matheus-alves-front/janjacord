import { describe, it, expect } from "vitest";
import { evaluatePermission, canModify } from "../src/index.js";
import type { Role, Channel } from "@janjacord/schemas";

const owner: Role = { id: "owner", name: "Owner", level: 100, permissions: [] };
const admin: Role = { id: "admin", name: "Admin", level: 80, permissions: ["manage_invites", "kick_members", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera"] };
const member: Role = { id: "member", name: "Member", level: 10, permissions: ["view_channel", "send_messages", "join_call", "speak"] };

const channel: Channel = {
  id: "ch1",
  serverId: "s1",
  type: "text",
  name: "staff",
  createdAt: 1,
  overrides: [
    { roleId: "member", allow: [], deny: ["view_channel"] },
    { roleId: "admin", allow: ["view_channel"], deny: [] },
  ],
};

describe("evaluatePermission", () => {
  it("deny do canal vence allow da role (precedência)", () => {
    expect(evaluatePermission({ identityId: "m", roleId: "member", isOwner: false }, member, channel, "view_channel")).toBe(false);
  });

  it("allow explícito do canal vence server default", () => {
    const noView: Role = { ...member, permissions: ["send_messages"] };
    expect(evaluatePermission({ identityId: "a", roleId: "admin", isOwner: false }, admin, channel, "view_channel")).toBe(true);
    // admin sem override no canal mas com flag na role
    const ch2: Channel = { ...channel, overrides: [], createdAt: 2 };
    expect(evaluatePermission({ identityId: "a", roleId: "admin", isOwner: false }, admin, ch2, "manage_invites")).toBe(true);
    void noView;
  });

  it("member sem permissão não acessa", () => {
    expect(evaluatePermission({ identityId: "m", roleId: "member", isOwner: false }, member, null, "send_files")).toBe(false);
  });

  it("owner sempre vence", () => {
    expect(evaluatePermission({ identityId: "o", roleId: "owner", isOwner: true }, owner, channel, "view_channel")).toBe(true);
  });
});

describe("canModify", () => {
  it("admin kicka member mas não owner", () => {
    expect(canModify({ identityId: "a", roleId: "admin", isOwner: false, role: admin }, member, "kick_members")).toBe(true);
    expect(canModify({ identityId: "a", roleId: "admin", isOwner: false, role: admin }, owner, "kick_members")).toBe(false);
  });

  it("member não kicka", () => {
    expect(canModify({ identityId: "m", roleId: "member", isOwner: false, role: member }, member, "kick_members")).toBe(false);
  });
});
