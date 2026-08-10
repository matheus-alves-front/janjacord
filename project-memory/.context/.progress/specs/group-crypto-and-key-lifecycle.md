# SPEC — Group Crypto and Key Lifecycle (MLS)

## 1. Slice identity

- Slice / feature / artifact: E2EE de grupo, hierarquia de chaves, lifecycle de epochs/devices
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/crypto` (futuro)
- Product truth source: PRODUCT.md §2 (Text E2EE; Identity), contrato congelado §24, §27
- Architecture truth source: ARCHITECTURE.md (crypto boundary; group state)
- Checklist phase/item: Phase 1 (crypto adapter), Phase 3 (text)
- Primary actor / audience: membros do canal, JanjaNode (como Delivery Service, não confiável)
- Final-user outcome: E2EE de grupo padrão com FS/PCS; host não lê nada
- Why this matters now: decisão mais sensível do produto; proibido protocolo criptográfico próprio

## 2. Confirmed facts (pesquisa 2026-08-09 — MlsScout)

- **Recomendação: MLS (RFC 9420) com core único em Rust — `mls-rs` (awslabs) — compartilhado
  entre desktop e mobile, bindings distintos por plataforma:**
  - Desktop (Electron/Node/TS): **WASM** (mls-rs é WASM first-class; Node 22+ executa wasm
    nativamente; mesmo `.wasm` roda no main e renderer sem rebuild ABI). Alternativa de
    performance: addon nativo via napi-rs (empacotamento por SO/arch).
  - Mobile (React Native): **UniFFI** gerando Kotlin (Android) + Swift (iOS) do core Rust,
    expostas como TurboModule. **NÃO apostar em WASM no RN** (Hermes WASM experimental;
    spike obrigatório antes de qualquer caminho wasm no mobile).
  - Alternativa equivalente: `openmls` (MIT, Phoenix R&D + Cryspen) — CI testa só x86;
    mobile/wasm buildados sem teste.
  - wrapper TS fino (interface comum) consumido por desktop e mobile.
- **Maturidade/risco:** mls-rs 0.55.3 (Apache-2.0/MIT, AWS Labs, interop oficial do IETF MLS
  WG no CI) — **sem auditoria externa publicada** (declarado no README); breaking changes
  entre minors (pin de versão + testes de interop contínuos); planejar auditoria externa antes
  de V1. mls-rs-uniffi (wrapper alto nível) parado desde 2024 → manter wrapper próprio.
- **libsignal rejeitado como base de grupo:** Signal Protocol (Double Ratchet/X3DH) tem FS
  limitada e PCS O(n²) em grupos, sem key establishment assíncrono nativo, AGPL-3.0 (copyleft),
  uso fora da Signal não suportado. MLS atende grupos dinâmicos + offline + multi-device
  diretamente.
- **Multi-device no MLS:** cada device é um **client/leaf distinto** (KeyPackage: signature key
  + HPKE encryption key + credential) — RFC 9420 §10; RFC 9750 §6.7: novo device não ganha
  histórico. Mesma identidade em N devices resolvida no **Authentication Service (AS)** que
  atesta binding ID→chaves (RFC 9750 §2.2, §4). Adição = Add com KeyPackage; remoção =
  Remove; rotação = Update; recovery pós-perda = rejoin + Remove do leaf antigo (+ PSK opcional).
- **Trade-off (RFC 9750 §8.2.4):** device-per-leaf expõe a outros membros/DS qual device enviou
  e quando devices entram/saem (correlação). Alternativa (compartilhar estado entre devices =
  aparecer como um client) aumenta risco de lockout total. **JanjaCord: device-per-leaf**
  (revogação granular; decisão de produto registrada).
- **JanjaNode = Delivery Service strongly consistent (RFC 9750 §5.2):** single-writer na ordem
  de Commits (RFC 9420 §14: Commits conflitantes formam fork que MLS não mergeia — prevenção é
  a via); réplicas de failover preservam a mesma ordem total (alinha com ReplicationScout).
- **Privacidade:** sender data é criptografado no PrivateMessage (RFC 9420 §16.3 — DS não vê o
  remetente); handshakes como PrivateMessage reduzem metadata (RFC 9750 §6.4); DS pode
  reordenar/particionar/omitir (detectável só por comparação out-of-band do
  `epoch_authenticator` — RFC 9420 §16.9/§16.10).
- **Read-once:** MLS não purga ciphertext; FS intra-epoch vem da deleção de chaves após uso
  (RFC 9420 §16.6); **o purge do conteúdo no host/peers é responsabilidade do transporte**
  (specs read-once/purge).

## 3. Open decisions

- Hierarquia de chaves (a decidir na arquitetura; MLS exige): identity seed (vault) →
  assinatura (credencial BasicCredential) + HPKE (KeyPackage) por device; PSK opcional de
  recovery. Senha protege o vault (fora do MLS).
- AS do JanjaCord: o JanjaNode (host do server, um peer) assina as credenciais que ligam cada
  device-leaf a um user-id do server — documentar que o AS vê binding (não conteúdo).
- Cipher suite: X25519 + AES-GCM/ChaCha20-Poly1305 (suites 1-3 mls-rs); provider rustcrypto
  (WASM) — confirmar no spike.

## 4. Real behavior contract

- Entry point: membro autorizado envia mensagem em canal (ou muda membership).
- Main actions:
  1. Mensagem: cifrada com o estado do grupo (epoch atual) → PrivateMessage (sender data
     cifrado) → envelope de transporte → peers/spool.
  2. Membership change (add/remove/update/ban): proposal + Commit (single-writer via JanjaNode
     DS) → novo epoch → membros atualizam estado.
  3. Device novo: Add com KeyPackage (via linking); device revogado: Remove.
  4. Recovery: rejoin como novo membro + Remove do leaf antigo; PSK de prova opcional.
  5. Deleção de chaves após uso (FS intra-epoch); purge de ciphertext no transporte.
- Data required: grupo MLS por canal (estado persistido cifrado — sqlite feature do mls-rs),
  KeyPackages, credenciais, epochs.
- Persistence or side effect: estado MLS persistido (SQLCipher); nada plaintext.
- Integrations/API calls: mls-rs (WASM/UniFFI), storage, transporte, AS (JanjaNode).
- Completion state: mensagem cifrada para a audiência; membership changes refletidas;
  device revogado sem acesso futuro.
- What must not be mocked: cifragem real MLS, Commits reais, FS real.

## 5. Required states and failures

- Loading: estado MLS carregando (persistência).
- Empty: grupo criado no primeiro membro.
- Error: epoch desatualizada (mensagem de outro epoch) → pedir estado atual; Commit divergente
  → rejeitar (single-writer).
- Invalid input: n/a.
- Unauthorized: membro fora da audiência não descriptografa (nem tenta).
- Slow dependency: Commit aguardando host; async members recebem no reconnect.
- Partial failure: Commit aplicado mas membro offline → entrega no reconnect (out-of-order
  suportado via feature rfc_compliant).
- Retry/recovery: membro forked rejoin via external commit; device perdido → recovery.

## 6. Acceptance criteria

- [ ] Mensagem cifrada com MLS (RFC 9420) — sem protocolo próprio
- [ ] Novo membro/device NÃO ganha acesso retroativo (RFC 9750 §6.7)
- [ ] Device revogado perde acesso a estados futuros (Remove efetivo)
- [ ] Commits conflitantes prevenidos (single-writer; fork rejeitado)
- [ ] Host (DS) não vê remetente (sender data cifrado) nem conteúdo
- [ ] Estado MLS persistido cifrado (SQLCipher); chaves deletadas após uso (FS)
- [ ] Mesma identidade multi-device opera no grupo (device-per-leaf)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: crypto mock, "GroupEncryptionService" caseiro.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: auditoria externa de segurança (orçar); spike WASM/UniFFI
  antes de congelar bindings.

## 8. Client/public language gate

- Terms that must not appear: "MLS", "KeyPackage", "epoch" na UI.
- Claims that require proof: "E2EE de grupo" — protocolo padrão + auditoria.
- Buyer/client language replacements: "conteúdo cifrado de ponta a ponta".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de interop MLS (adapters desktop/mobile)
- Teste de membership change (add/remove/ban) com multi-device
- Teste de FS/PCS (chaves deletadas; device revogado sem acesso)
- Spike: WASM no Electron + UniFFI no RN

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 1, Phase 3
- Item(s): crypto adapter, MLS grupo, key lifecycle, multi-device
- Acceptance rule: `[x]` com testes de interop + security review
- Evidence links: SECURITY-REVIEW; QA-REVIEW

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (crypto boundary; group state)
- INTEGRATIONS.md: sim (mls-rs, UniFFI, SQLCipher)
- ADR required: ADR-005 (group E2EE standard protocol) — gate security obrigatório
- Operator packet required: sim (M1 valida E2EE real)
