import { describe, expect, it } from "vitest";
import {
  buildProviderConfig,
  clearSensitiveFields,
  connectivityErrorMessage,
  isValidHostname,
  providerBlockReason,
  sanitizeEndpoint,
} from "./ConnectivityWizard";

const emptyForm = { token: "", domain: "", cloudflareMode: "quick" as const };

describe("connectivity provider configuration", () => {
  it("builds only the configuration required by each provider", () => {
    expect(buildProviderConfig("tailscale", emptyForm)).toEqual({});
    expect(buildProviderConfig("ngrok", { ...emptyForm, token: "  secret-token  " })).toEqual({ token: "secret-token" });
    expect(buildProviderConfig("ngrok", emptyForm)).toEqual({});
    expect(buildProviderConfig("cloudflare", { ...emptyForm, token: "ignored", domain: "ignored.example" })).toEqual({ mode: "quick" });
    expect(buildProviderConfig("cloudflare", {
      token: " named-secret ",
      domain: " Chat.Example.com. ",
      cloudflareMode: "named",
    })).toEqual({ mode: "named", token: "named-secret", hostname: "chat.example.com" });
    expect(buildProviderConfig("manual", { ...emptyForm, domain: " Host.Example.com. " })).toEqual({ domain: "host.example.com" });
  });

  it("removes secrets from form state immediately after submission", () => {
    expect(clearSensitiveFields({ token: "never-render-again", domain: "chat.example.com", cloudflareMode: "named" })).toEqual({
      token: "",
      domain: "chat.example.com",
      cloudflareMode: "named",
    });
  });

  it("requires only prerequisites that the selected flow cannot supply", () => {
    expect(providerBlockReason({ id: "tailscale", installed: false }, emptyForm)).toMatch(/não foi detectado/i);
    expect(providerBlockReason({ id: "tailscale", installed: true, authenticated: false }, emptyForm)).toMatch(/entre no tailscale/i);
    expect(providerBlockReason({ id: "ngrok", installed: true, authenticated: false }, emptyForm)).toMatch(/authtoken/i);
    expect(providerBlockReason(
      { id: "ngrok", installed: true, authenticated: false },
      { ...emptyForm, token: "supplied-now" },
    )).toBeNull();
    expect(providerBlockReason(
      { id: "cloudflare", installed: true },
      { token: "secret", domain: "chat.example.com", cloudflareMode: "named" },
    )).toBeNull();
    expect(providerBlockReason(
      { id: "cloudflare", installed: true, authenticated: true },
      { token: "", domain: "chat.example.com", cloudflareMode: "named" },
    )).toBeNull();
    expect(providerBlockReason(
      { id: "manual", installed: false },
      { ...emptyForm, domain: "chat.example.com" },
    )).toBeNull();
  });
});

describe("connectivity display safety", () => {
  it("accepts hostnames but rejects URLs and malformed labels", () => {
    expect(isValidHostname("chat.example.com")).toBe(true);
    expect(isValidHostname("Node.EXAMPLE.com.")).toBe(true);
    expect(isValidHostname("https://chat.example.com/path")).toBe(false);
    expect(isValidHostname("-chat.example.com")).toBe(false);
    expect(isValidHostname("localhost")).toBe(false);
  });

  it("never renders credentials, query tokens, fragments or malformed endpoints", () => {
    expect(sanitizeEndpoint("wss://user:pass@chat.example.com/socket?token=secret#private")).toBe("wss://chat.example.com/socket");
    expect(sanitizeEndpoint("not an endpoint with secret-token")).toBe("Endpoint protegido");
  });

  it("turns provider failures into actionable messages without exposing raw details", () => {
    expect(connectivityErrorMessage({ code: "quota", message: "account 123 secret" }, "Falhou")).toMatch(/cota/i);
    expect(connectivityErrorMessage({ code: "process_exited", message: "--token secret" }, "Falhou")).toMatch(/encerrado/i);
    expect(connectivityErrorMessage({ code: "unknown", message: "secret" }, "Falha segura")).not.toContain("secret");
  });
});
