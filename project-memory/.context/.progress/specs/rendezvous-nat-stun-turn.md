# SPEC — Rendezvous, NAT, STUN, TURN

## 1. Slice identity

- Slice / feature / artifact: infra central mínima — rendezvous + STUN + TURN + update
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `apps/rendezvous` + `infra/stun,turn` (futuro)
- Product truth source: PRODUCT.md §2 (Network privacy; Infra), contrato congelado §6, §8, §35, §39-§40
- Architecture truth source: ARCHITECTURE.md (central infra; transport)
- Checklist phase/item: fases de networking/infra
- Primary actor / audience: hosts (servers user-hosted), peers, operadores de infra
- Final-user outcome: peers e hosts se encontram e trocam media/dados sem storage central de conteúdo
- Why this matters now: define o tamanho e a superfície da infra central; trust boundary documentada

## 2. Confirmed facts (pesquisa 2026-08-09 — PushRendezvousScout)

- **Rendezvous** (padrão equivalente ao libp2p rendezvous — REGISTER/DISCOVER, TTL 2–72h,
  signed peer records, rate limits 1000 regs/peer, 1000 peers/query):
  - registro efêmero assinado pela host key; `serverId` = fingerprint da host key
  - TTL curto; rate limits por IP; bootstrap por DNS SRV/TXT (RFC 2782/6763)
  - lookup verifica assinatura no cliente; sem contas; nada de discovery de conteúdo
- **STUN** (RFC 8489) e **TURN** (RFC 8656): STUN descobre endereço público; TURN relay para
  symmetric NAT; TURN oculta endereço real do peer por construção.
- **coturn self-host** (deploy recomendado):
  - long-term credentials OBRIGATÓRIO via TURN REST API: username = `timestamp:user`,
    password = `base64(HMAC-SHA1(secret, username))` — credenciais de curta duração
  - portas: 3478 (UDP/TCP), 5349 (TLS), faixa de relay UDP default 49152–65535
  - relay-only: `iceTransportPolicy: 'relay'` no cliente + `--no-stun`/deny lists no servidor
  - `--user-quota`/`--total-quota`/`--denied-peer-ip` para abuso
- **Push** (ver também `mobile-ui-ux-contract.md`): serviço central de push é inevitável
  (credenciais FCM/APNs são por-app); payload 100% estático "New activity on JanjaCord";
  tokens nunca expostos ao JanjaNode (device usa capability ticket); retenção mínima.
- **Update**: Electron self-host de update server (update.electronjs.org exige repo GitHub
  público — inviável para app privado) com assinatura obrigatória no macOS; mobile via lojas.
- Nada de: messages/images/files/voice/video/search/social graph storage na central.

## 3. Open decisions

- Onde roda a infra central (nuvem própria vs VPS dedicada; geo): decisão de deploy futura
  (Phase 5+); arquitetura deve permitir self-host do rendezvous (open).
- Protocolo exato do rendezvous (wire): seguir modelo libp2p rendezvous (REGISTER/DISCOVER)
  com records assinados; definir formato no `realtime-networking-protocol.md`.
- Push service: componente central separado (`apps/push`?) — confirmar no monorepo:
  recomendado sim, módulo mínimo com FCM v1/APNs HTTP/2 e capability tickets.

## 4. Real behavior contract

- Entry point: host anuncia disponibilidade; cliente procura host por serverId.
- Main actions:
  1. Host (primary/replica) registra record assinado: serverId, endpoints (host:port),
     tipo (primary/replica), TTL curto.
  2. Cliente/peer: lookup por serverId → valida assinatura contra host key → conecta.
  3. ICE: coleta candidates (srflx via STUN; relay via TURN) → signaling → conexão.
  4. TURN REST API: credenciais temporárias (timestamp+HMAC), curta duração, renováveis.
  5. Push: JanjaNode envia ping assinado (sem conteúdo) ao push service → FCM/APNs com
     payload estático → device.
  6. Update: cliente consulta update server (assinado) / lojas.
- Data required: serverId, endpoints efêmeros, records assinados, TURN credentials, push tokens.
- Persistence or side effect: records com TTL (expiração), tokens de push com retenção mínima;
  sem storage de conteúdo.
- Integrations/API calls: coturn (TURN REST API), FCM/APNs, DNS SRV/TXT, update server.
- Completion state: peers conectados; host encontrável; push entregue sem conteúdo.
- What must not be mocked: assinatura de records, TURN real, push real com payload estático.

## 5. Required states and failures

- Loading: lookup em andamento; ICE coletando.
- Empty: host não registrado (offline) → erro "server offline".
- Error: assinatura inválida → rejeitar record; TURN indisponível → fallback conforme policy.
- Invalid input: serverId malformado.
- Unauthorized: n/a (assinatura valida identidade).
- Slow dependency: STUN lento; TURN sobrecarregado.
- Partial failure: TURN cai durante call → reconnect (direct preferred) ou fim de call (relay-only).
- Retry/recovery: host re-registra ao voltar; cliente re-faz lookup com backoff.

## 6. Acceptance criteria

- [ ] Host registra/expira no rendezvous com TTL; lookup valida assinatura
- [ ] Dois peers atrás de NAT se conectam com STUN (direct) ou TURN (relay)
- [ ] coturn com REST credentials de curta duração funciona; relay-only não emite candidates diretos
- [ ] Rendezvous não armazena conteúdo nem metadata durável de usuário
- [ ] Push entrega payload estático sem conteúdo; token nunca exposto ao JanjaNode
- [ ] Update self-host assinado funciona no desktop; lojas no mobile
- [ ] Rate limits de rendezvous contêm abuso (teste)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: rendezvous/TURN fake em operator test.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: teste real de NAT (dois hosts em redes distintas).

## 8. Client/public language gate

- Terms that must not appear: "zero metadata", "anonimato".
- Claims that require proof: "infra não lê conteúdo" — threat model + auditoria.
- Buyer/client language replacements: "bootstrap-only infrastructure", "self-hostable rendezvous".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste real de conectividade NAT (STUN direct; TURN relay; symmetric NAT)
- Teste de assinatura de records (rejeição de record forjado)
- Smoke de push com payload estático (Android + iOS)

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fases de infra/networking
- Item(s): rendezvous, STUN/TURN, push service, update
- Acceptance rule: `[x]` com smokes reais
- Evidence links: OPERATOR-TEST-PACKET; infra tests

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (central infra)
- INTEGRATIONS.md: sim (coturn, FCM/APNs, update)
- ADR required: ADR-003 (minimal central infrastructure) + ADR-007 (direct vs relay)
- Operator packet required: sim
