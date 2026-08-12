import { describe, expect, it, vi } from "vitest";
import { restoreConsumedInviteFocus } from "./Main";

describe("consumed invite focus recovery", () => {
  it("focuses Criar convite only after the invite card has unmounted", () => {
    const focus = vi.fn();
    const base = {
      pending: true,
      view: "server" as const,
      settingsOpen: false,
      button: { focus },
    };

    expect(restoreConsumedInviteFocus({ ...base, inviteKey: "JC3-active" })).toBe(false);
    expect(focus).not.toHaveBeenCalled();

    expect(restoreConsumedInviteFocus({ ...base, inviteKey: null })).toBe(true);
    expect(focus).toHaveBeenCalledOnce();
    expect(focus).toHaveBeenCalledWith({ preventScroll: true });
  });

  it("defers focus while settings cover the server view", () => {
    const focus = vi.fn();

    expect(restoreConsumedInviteFocus({
      pending: true,
      inviteKey: null,
      view: "server",
      settingsOpen: true,
      button: { focus },
    })).toBe(false);
    expect(focus).not.toHaveBeenCalled();
  });
});
