# PRODUCT.md — JanjaCord

> Verdade durável do produto. Fonte: contrato de definição congelado em 2026-08-09 (TASK-001).
> Não é log de execução. Decisões marcadas como LOCKED não devem ser reabertas sem conflito
> técnico/material documentado.

## 1. Product objective

- **Problema resolvido:** comunicação privada e efêmera em comunidades fechadas, sem
  dependência de infraestrutura central confiável para o conteúdo, sem telemetria e sem
  identidade real. O usuário quer um canal de conversa em que a infraestrutura não consiga
  ler nada e em que nada seja permanente por padrão.
- **Usuários primários:** comunidades pequenas (até dezenas de membros) que se conhecem por
  convite e querem conversar por texto, voz e vídeo com privacidade real: famílias, times de
  projeto, grupos de amigos, comunidades técnicas. Público técnico disposto a self-host e
  usuários comuns que só querem um app privado.
- **Outcome de negócio desta fase:** contrato de produto, arquitetura, specs e roadmap
  executáveis que tornem o produto impossível de ser mal interpretado antes da implementação.
- **Por que agora:** decisões de produto foram congeladas; a arquitetura precisa ser desenhada
  assumindo que o operador da infraestrutura não precisa ser confiável para preservar a
  confidencialidade do conteúdo.

**Frase arquitetural:** JanjaCord é um sistema invite-only de comunicação em comunidades, com
identidade pseudônima local, mensagens de grupo E2EE e efêmeras, e canais WebRTC P2P de
voz/vídeo. Servers são hospedados pelos próprios usuários através do JanjaNode, enquanto a
infraestrutura pública JanjaCord fornece apenas bootstrap/rendezvous e conectividade opcional.

**Frase de produto:** **Server. Channel. Talk. Nothing else.**

## 2. Scope

### Modelo mental (LOCKED)

```text
JanjaCord
   ↓
Server (comunidade criptográfica user-hosted)
   ↓
Channel
   ├── Text (efêmero, read-once, E2EE)
   └── Call (voice + câmera opcional, WebRTC mesh)
```

### In scope (V1 — LOCKED)

**Identity**
- nickname + senha como onboarding; identidade criptográfica de alta entropia gerada localmente
- vault local cifrado; senha protege o vault (nunca é a identidade criptográfica)
- recovery key exibida/exportável uma vez
- device linking desktop↔mobile por QR; device revocation
- nickname server-specific; autoridade interna é a identidade criptográfica

**Servers**
- create server; join via invite key; leave
- ownership + ownership transfer
- Primary Host (desktop do owner por padrão) + Replica Hosts autorizados
- member list; kick; ban (ban por identidade criptográfica, não por IP/email/hardware)

**Invites**
- chaves únicas; expiração; limites de uso; revogação; initial role

**Channels**
- text channel; call channel (voice + vídeo opcional); private channels; channel permission overrides

**Text (núcleo do produto)**
- E2EE de grupo (protocolo padrão; MLS candidato — ver specs/ADR)
- entrega P2P realtime (WebRTC DataChannel) + spool cifrado temporário no host
- audience snapshot: a mensagem pertence aos membros autorizados no instante do envio;
  novos membros NÃO recebem conteúdo anterior
- read-once: consumida → some; purge global quando todos os destinatários elegíveis consumirem
- maximum retention configurável (1h/24h/7d/30d; default 7d)
- replies; reactions (👍 😂) com o mesmo lifecycle efêmero

**Media**
- imagens e arquivos genéricos; cifrados localmente; P2P ou spool cifrado temporário
- Save/Copy/Download/Share (mobile) conforme plataforma

**Voice/Video**
- group voice; group video; camera on/off; mute/deafen/leave
- mesh P2P WebRTC na V1; guardrails iniciais: ~10 voz, ~6 câmeras (a medir, não imutáveis)

**Network privacy**
- direct preferred; relay only (policy por server); ICE/STUN/TURN; self-hosted TURN; fallback relay JanjaCord explícito

**Roles & permissions**
- Owner/Admin/Moderator/Member + custom roles; hierarchy; permission flags (não `if role === "admin"`)
- kick/ban; channel overrides

**Privacy (não negociável)**
- sem email/telefone; sem descoberta pública (servers nem usuários); sem read receipts visíveis;
  sem typing indicator; sem analytics; sem telemetria; sem logging de conteúdo; sem chamadas
  gravadas; sem histórico permanente; push genérico opt-in sem conteúdo

**Plataformas:** Windows, macOS, Linux (Electron); Android, iOS (React Native/Expo)

### User-defined milestones

- **MVP testável técnico:** fatia real — Desktop A cria identidade + server self-hosted + invite;
  Desktop B cria identidade + entra; ambos em #general; mensagem E2EE real; recipient consome;
  lifecycle/purge funciona; nenhum plaintext no host spool. Sem fake data, sem mock network.
- **V1 alpha:** texto completo + presença + invites + roles/permissions + replicas mínimas.
- **V1 beta:** voz + vídeo mesh + attachments + multi-device + push genérico.
- **V1 release:** tudo da V1 (ver seção 2 "In scope") nos 5 SOs, com operator-test packets.
- **V1.1 candidato:** screen share (primeiro candidato; não mover itens V1 sem motivo+impacto+evidência).

### Out of scope (V1 — LOCKED)

DMs; friends system; public servers; server discovery; profiles/bios/status; screen sharing;
streaming; bots; plugins; webhooks; threads; forums; stickers; GIF browser; custom emoji
platform; voice notes; message history/search; events/calendar; stages; broadcast rooms;
large-scale conferencing; SFU central obrigatório; public web client.

Provavelmente nunca: public discovery, social graph, engagement mechanics.

### Constraints

- **Segurança/privacidade:** E2EE real (sem backdoor central); sem recovery central de private keys;
  threat model público; infraestrutura não lê conteúdo; metadata mínima justificada.
- **Técnica:** sem protocolo criptográfico próprio; implementações maduras revisadas; WebRTC mesh
  com limites defensivos; rodar nos 5 SOs com custo central marginal pequeno.
- **Legal/compliance:** licença open-source a definir sem bloquear arquitetura; push via APNs/FCM
  documenta trust boundary; sem fingerprinting invasivo.
- **Produto:** "Server. Channel. Talk. Nothing else." — qualquer feature que crie mecanismo de
  engajamento está fora.

## 3. Actors and permissions

### Identity local (usuário)

- Cria identidade pseudônima (nickname + senha), gera recovery key, linka devices.
- **Cannot:** ser descoberto globalmente; recuperar identidade sem recovery material.

### Server Owner

- Cria o server; é Primary Host por padrão; transfere ownership; configura políticas (retenção,
  privacy mode); promove Replica Hosts.
- **Cannot:** ler conteúdo que não esteja criptograficamente autorizado por ser host.

### Admin / Moderator

- Permissions por flags (manage_*, kick, ban, assign_roles, etc.).
- **Cannot:** rebaixar Owner; ler conteúdo sem autorização criptográfica.

### Member

- Entra por invite; vê canais conforme permissão; conversa; sai quando quiser.
- **Cannot:** ver conteúdo anterior à entrada; ver read receipts; ver typing indicators.

### Infraestrutura central JanjaCord (rendezvous/STUN/TURN/update)

- Só bootstrap/rendezvous/conectividade/updates.
- **Cannot:** ler mensagens, imagens, arquivos, voz, vídeo; manter conteúdo; telemetria de usuário.

### Host Node / Replica Host

- Coordena membership, entrega, presence, signaling; mantém ciphertext temporário.
- **Cannot:** ler plaintext dos canais que hospeda sem ser endpoint autorizado.

## 4. End-to-end flow (primeiro fluxo crítico — MVP testável)

1. **Entry point:** primeira abertura → Welcome → nickname + senha → Create identity
   (gera keypair + device key + account id + vault local cifrado; recovery key mostrada uma vez).
2. **Create server:** `+` → Create server → vira Owner + Primary Host (JanjaNode ativado).
3. **Invite:** Owner gera invite key (JC1-…, com expiração/limites/initial role).
4. **Join:** Desktop B → `+` → Add server → cola invite key → entra como Member.
5. **Conversation:** ambos em #general → Alice envia mensagem → E2EE local → envelope com
   audience snapshot → P2P DataChannel (online) + spool cifrado (offline) → Bruno recebe,
   autentica, descriptografa, renderiza → CONSUMED ACK → quando todos consumirem → purge.
6. **Completion:** mensagem deixa de existir no sistema (host ciphertext, replicas, receipt state).

## 5. Business rules (LOCKED)

1. **Read once:** mensagem pertence à audiência do instante do envio; cada destinatário consome
   uma vez; ao sair do canal, plaintext local e cache de attachments são destruídos; reabrir o
   canal não reapresenta mensagens já consumidas.
2. **Audience snapshot imutável:** novos membros não recebem conteúdo anterior; membro removido
   sai da audiência pendente e perde capacidade criptográfica futura.
3. **Purge:** todos consumiram → purge imediato (host + replicas + receipt state); senão, maximum
   retention (default 7d) → hard purge.
4. **Efemeridade não é DRM:** JanjaCord controla apenas cópias mantidas pelo JanjaCord; copy/save/
   share/screenshot/gravação externa não são revertidos.
5. **Identidade ≠ senha:** senha humana tem entropia insuficiente; nunca derivar identidade de
   nickname+senha; senha apenas protege o vault.
6. **Zero telemetria:** sem analytics/tracking/read analytics/behavior history; debugging local
   explícito e sanitizado; crash report opt-in manual.
7. **Sem promessa de anonimato:** content-private, pseudonymous, metadata-minimizing; metadados de
   transporte existem em redes IP (threat model).
8. **Server = comunidade criptográfica:** não é VM central; quem cria é Owner + Primary Host por
   padrão; replicas autorizadas para continuidade.
9. **Ban por identidade criptográfica:** não por IP/email/telefone/hardware fingerprint.
10. **Push genérico:** opt-in; sem conteúdo/sender/server/channel name.
11. **Nenhum conteúdo legível pela infraestrutura:** operador central não precisa ser confiável
    para confidencialidade.
12. **Roles via permission flags**, com hierarchy e channel overrides; precedence definida e testável.

## 6. Required edge cases (V1)

- loading/pending (primeira abertura, criação de identidade, join)
- empty states (sem servers, canal vazio, sem members)
- invalid input (invite inválido/expirado/revogado; senha fraca; nickname duplicado no server)
- duplicate action (join duplicado; invite já usado; reação duplicada)
- timeout/slow dependency (host offline; STUN/TURN indisponível; rendezvous inacessível)
- unauthorized/forbidden (sem permissão de canal; banido; kickado; invite sem initial role)
- partial failure (spool parcial; attachment interrompido; replica divergente)
- retry/recovery (host reinicia; replica promovida; device perdido; recovery key; app crash
  durante consumption; reconnect durante call)
- member removido antes de consumir; mensagem que expira por retenção com membro ausente
- app em background (mobile) com push genérico; consumo vs apresentação (RECEIVED vs CONSUMED)
- relay-only com TURN self-host caindo; fallback público deve ser explícito

## 7. Acceptance criteria (V1 release)

- [ ] Dois desktops + um mobile representam a mesma identidade (device linking) e conversam no mesmo server
- [ ] Mensagem enviada em #general chega somente à audiência do instante; novo membro não a recebe
- [ ] Mensagem some de host + replicas após todos consumirem ou após max retention
- [ ] Nenhum plaintext de mensagem/imagem/arquivo existe em host, replica, rendezvous ou central
- [ ] Voz/vídeo em grupo funcionam em mesh P2P (mute, deafen, camera on/off, leave) com limites de guardrail
- [ ] Invite com expiração/limites/revogação se comporta como especificado; ban impede reentrada da mesma identidade
- [ ] Roles/permissions com overrides de canal respeitam precedence definida
- [ ] Sem analytics SDK, sem telemetria, sem read receipts visíveis, sem typing indicator
- [ ] Push mobile é genérico ("New activity on JanjaCord"), opt-in, sem conteúdo
- [ ] Ownership transfer funciona sem perder controle nem quebrar hosts
- [ ] Host offline → replica promovida (ou comportamento documentado) sem divergência que quebre crypto
- [ ] App roda nos 5 SOs com fluxos operator-testáveis documentados (OPERATOR-TEST-PACKET por milestone)

## 8. Optional creative / asset acceptance criteria

- Visual target: **modern private communication tool** — linguagem shadcn/ui (limpa, minimalista,
  densa, ótimos estados, dark mode excelente); NÃO copiar Discord; NÃO estética hacker/cyberpunk.
- References: shadcn/ui design language; identidade própria (paleta a definir no UI/UX contract).
- Required surfaces: onboarding/identity, server rail, channel list, conversation, call grid,
  settings/members/invites, empty/error states.
- Blocker threshold: UI genérica, template feel, placeholder copy ou visual "hacker" bloqueiam o
  gate de UI/UX antes de frontend.

## 9. Open product decisions (resolvidas tecnicamente, não reabertas)

- Todas as decisões de produto da seção 2 estão LOCKED (contrato 2026-08-09).
- Decisões técnicas em aberto (a resolver na arquitetura/specs): implementação MLS; hierarquia de
  chaves; vault; protocolo de device linking; consistência de replicação; wire protocol; push
  backend; rendezvous. Nenhuma exige decisão de produto nova.

## 10. Operational policy needs

- External mutable tools in scope: APNs/FCM (push), STUN/TURN/rendezvous (infra própria), stores
  (distribuição). Sem Trello/Canva/Figma/payments nesta fase.
- External writes policy: `preauthorized_controlled` só quando houver infra real (futuro); nesta
  operação: nenhum write externo.
- AI runtime policy: N/A (produto sem runtime de IA; ML/IA fora de V1).
- UI/UX evidence artifact required for release: sim — UI-UX-EVIDENCE por milestone visual.
- Operator-test packets: obrigatórios (MVP testável, alpha, beta, release).

---

## Referência cruzada

- Specs: `specs/` (product contract, identity, hosting, invites, permissions, read-once,
  consumption/purge, attachments, crypto, networking, webrtc, rendezvous, privacy, UI/UX...)
- Decisões arquiteturais: `adr/`
- Roadmap: `CHECKLIST.md`
- Integrações: `INTEGRATIONS.md`
