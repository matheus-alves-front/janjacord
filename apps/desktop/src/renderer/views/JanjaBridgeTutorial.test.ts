import { describe, expect, it } from "vitest";
import { JANJABRIDGE_SETUP_COMMANDS } from "./JanjaBridgeTutorial";

describe("JanjaBridge tutorial command contract", () => {
  it("keeps the displayed runbook aligned with the real bundle scripts", () => {
    expect(JANJABRIDGE_SETUP_COMMANDS.initialize).toContain("./scripts/init.sh");
    expect(JANJABRIDGE_SETUP_COMMANDS.start).toContain("docker compose up -d --build");
    expect(JANJABRIDGE_SETUP_COMMANDS.start).toContain("./scripts/issue-certificate.sh");
    expect(JANJABRIDGE_SETUP_COMMANDS.pairing).toBe("./scripts/mint-pairing.sh 24");
    expect(JANJABRIDGE_SETUP_COMMANDS.diagnose).toBe("docker compose logs --since=15m gateway rendezvous coturn");
  });

  it("does not put bridge secrets in copyable tutorial commands", () => {
    const commands = Object.values(JANJABRIDGE_SETUP_COMMANDS).join("\n");
    expect(commands).not.toMatch(/pairing-admin-key|turn-shared-secret|bridge-signing-key|\.env/);
  });
});
