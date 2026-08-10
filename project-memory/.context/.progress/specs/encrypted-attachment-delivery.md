# SPEC — Encrypted Attachment Delivery

## 1. Slice identity

- Slice / feature / artifact: imagens e arquivos genéricos — cifragem, transferência, lifecycle
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/protocol,storage` (futuro)
- Product truth source: PRODUCT.md §2 (Media), contrato congelado §25-§26, §28-§29
- Architecture truth source: ARCHITECTURE.md (media lifecycle; spool)
- Checklist phase/item: Phase 5 — Attachments
- Primary actor / audience: membros com `send_files`; receptores com acesso ao canal
- Final-user outcome: imagem/arquivo transferido de forma cifrada, efêmero, com retry
- Why this matters now: spool de attachments é custo real do host; precisa de limites e cleanup

## 2. Confirmed facts (pesquisa 2026-08-09 — WebRtcScout + StorageScout)

- DataChannel: mensagens grandes devem ser **fragmentadas (teto prático 16–64 KiB)** com
  backpressure via `bufferedAmount`; reliable+ordered para conteúdo (RFC 8831 U-C5).
- Offline: DC não cobre (sem PeerConnection) → spool cifrado no host com TTL + purge.
- SQLite cifrado (SQLCipher raw key) para metadata efêmera; attachments grandes podem ficar
  fora do banco (arquivo cifrado) — metadados/tamanhos não devem vazar em plaintext.
- Purge: `PRAGMA secure_delete` + VACUUM periódico; WAL/journal cifrados pelo SQLCipher.
- iOS Keychain persiste pós-uninstall → efêmeros devem ser purgados no app data também.
- Guardrails (spec abuse): size limits, quotas por server, TTL alinhado à retention.

## 3. Open decisions

- Formato de chunking do protocolo (tamanho do chunk, checksum por chunk, reassembly):
  - Why: retry parcial, integridade, DoS.
  - Options: (a) chunks de 64 KiB com checksum por chunk + manifest; (b) chunk menor com mais
    metadata. Recomendado: (a) — alinhado ao teto do DC; manifest com messageId, assetId,
    tamanho total, hash final. Owner: architect + security. Blocking: sim (protocolo).
- Size limits exatos (default): proposta 50 MB/arquivo, 2 GB/server (configurável) — calibrar
  em benchmarks; storage quota do host com cleanup. Owner: architect + platform. Blocking: sim.
- Cifragem: AES-256-GCM com asset key aleatória por arquivo; key referenciada no envelope da
  mensagem (cifrada para a audiência via MLS). Chunk-level AEAD vs arquivo inteiro:
  recomendado arquivo inteiro (GCM) + chunks de transporte autenticados por manifest.
  Owner: security. Blocking: sim.

## 4. Real behavior contract

- Entry point: usuário com `send_files` anexa imagem/arquivo.
- Main actions:
  1. Gera asset key aleatória (32 B) por arquivo; cifra localmente (AES-256-GCM).
  2. Divide em chunks (64 KiB) com checksum; cria manifest (assetId, tamanho, hash, chunks).
  3. Envia: P2P via DC (online) ou spool host (offline), com retry por chunk.
  4. Receptores: montam, verificam hash, descriptografam localmente, renderizam/salvam.
  5. Lifecycle: purge quando a mensagem for purgada (todos consumiram ou TTL); cleanup de
     chunks órfãos; quotas respeitadas.
- Data required: asset key, chunks cifrados, manifest, TTL/quotas.
- Persistence or side effect: ciphertext temporário no host/replicas; nada permanente.
- Integrations/API calls: DC/spool, storage (SQLite cifrado + file system), MLS (key ref).
- Completion state: arquivo íntegro entregue; ciphertext purgado com a mensagem.
- What must not be mocked: cifragem real, retry real, cleanup real, size limit real.

## 5. Required states and failures

- Loading: upload/progresso por chunk.
- Empty: n/a.
- Error: arquivo acima do limite → recusa antes do upload; hash mismatch → retry do chunk.
- Invalid input: chunk fora de ordem → reorder por índice; duplicado → ignorar.
- Unauthorized: receptor fora da audiência não recebe (host não entrega).
- Slow dependency: DC lento (backpressure); host offline (spool).
- Partial failure: upload interrompido → retry idempotente por chunk (assetId+chunkIndex).
- Retry/recovery: spool reenviado no reconnect; órfãos limpos por TTL.

## 6. Acceptance criteria

- [ ] Arquivo cifrado localmente (asset key aleatória); host só vê ciphertext
- [ ] Transferência P2P e via spool funciona com retry por chunk e reassembly íntegro
- [ ] Hash mismatch é detectado e corrigido (retry do chunk)
- [ ] Arquivo acima do limite é recusado antes de consumir storage relevante
- [ ] Quota de spool respeitada; cleanup remove órfãos no TTL
- [ ] Purge remove ciphertext de attachment junto com a mensagem
- [ ] Save/Copy/Download/Share funcionam conforme plataforma (UX spec)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: transferência simulada, cifragem mock, limite decorativo.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: benchmark de quotas.

## 8. Client/public language gate

- Terms that must not appear: "blob", "chunk" na UI.
- Claims that require proof: "host não vê arquivo" — teste de spool.
- Buyer/client language replacements: "arquivos e imagens com privacidade", "temporários".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de chunking/retry/hash (vitest)
- Teste de cleanup/quotas
- Operator-test: enviar imagem/arquivo P2P e offline (spool), verificar purge

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 5
- Item(s): cifragem, chunking, retry, limites, cleanup, UX
- Acceptance rule: `[x]` com testes + operator-test
- Evidence links: QA-REVIEW; OPERATOR-TEST-PACKET

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (media lifecycle)
- INTEGRATIONS.md: sim (SQLCipher)
- ADR required: ADR (attachment transport) — previsto
- Operator packet required: sim
