import { describe, expect, it } from "vitest";
import { presentHostIdentity, shortDeviceId } from "./ServerSettings";

describe("host identity presentation", () => {
  const me = { identityId: "identity-owner", nickname: "Matheus" };
  const members = [
    { identityId: "identity-owner", nickname: "Matheus" },
    { identityId: "identity-alice", nickname: "Alice" },
  ];

  it("derives a short stable device ID from the host identity", () => {
    const hostId = "host-0123456789abcdef01234567";

    expect(shortDeviceId(hostId)).toBe("0123-4567");
    expect(shortDeviceId(hostId)).toBe(shortDeviceId(hostId));
  });

  it("combines the current member nickname with the short device ID", () => {
    expect(presentHostIdentity(
      "identity-alice",
      "host-0123456789abcdef01234567",
      members,
      me,
    )).toEqual({
      nickname: "Alice",
      deviceId: "0123-4567",
      label: "Alice · dispositivo 0123-4567",
    });
  });

  it("uses a safe label when the host member is no longer listed", () => {
    expect(presentHostIdentity(
      "identity-removed",
      "host-fedcba987654321001234567",
      members,
      me,
    )).toEqual({
      nickname: "Membro não disponível",
      deviceId: "FEDC-4567",
      label: "Membro não disponível · dispositivo FEDC-4567",
    });
  });

  it("keeps the signed-in member nickname as a safe self fallback", () => {
    expect(presentHostIdentity(
      "identity-owner",
      "host-own-device",
      [],
      me,
    ).label).toBe("Matheus · dispositivo OWND-VICE");
  });
});
