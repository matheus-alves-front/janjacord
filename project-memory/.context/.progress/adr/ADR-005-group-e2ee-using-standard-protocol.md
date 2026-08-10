# ADR-005 — Group E2EE Using a Standard Protocol (MLS)

- **Status:** accepted (2026-08-09) — **security gate obrigatório**
- **Contexto:** E2EE de grupo com membership dinâmico, membros offline, multi-device, sem
  servidor confiável. Proibido protocolo criptográfico próprio.
- **Decisão:** MLS (RFC 9420) com core único em Rust — **mls-rs** (awslabs, Apache-2.0/MIT) —
  compartilhado entre plataformas: WASM no Electron, UniFFI (Kotlin/Swift) no React Native,
  wrapper TS fino (`packages/crypto`). JanjaNode atua como Delivery Service strongly consistent
  (single-writer de Commits, RFC 9420 §14 / RFC 9750 §5.2). device-per-leaf (RFC 9750 §6.7).
  libsignal rejeitado (AGPL, grupos, PCS O(n²)). openmls como alternativa equivalente.
- **Consequências:** FS/PCS por construção; novo device sem histórico; revogação granular;
  sender data cifrado (DS não vê remetente). Riscos: sem auditoria externa publicada
  (mls-rs) — planejar auditoria antes de V1; breaking changes pré-1.0 (pin + interop CI);
  spike WASM/UniFFI antes de congelar bindings; custo de CI Rust multiplataforma no mobile.
- **Spec:** `group-crypto-and-key-lifecycle.md`
- **Refs:** RFC 9420, RFC 9750; github.com/awslabs/mls-rs; github.com/openmls/openmls
