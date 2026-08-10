# SPEC — Mobile UI/UX Contract

## 1. Slice identity

- Slice / feature / artifact: contrato de UI/UX do mobile (React Native/Expo)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `apps/mobile` (futuro)
- Product truth source: PRODUCT.md §2 (Plataformas; Mobile), contrato congelado §46-§47, §50
- Architecture truth source: ARCHITECTURE.md (RN/expo; secure storage; push)
- Checklist phase/item: fases mobile
- Primary actor / audience: usuário Android/iOS
- Final-user outcome: mesma linguagem visual do desktop, com navegação nativa simples
- Why this matters now: gate de UI/UX antes de frontend mobile

## 2. Confirmed facts

- Stack: React Native + Expo tooling + TypeScript; development builds/native modules para
  WebRTC e crypto (não ficar preso ao Expo Go).
- NÃO reutilizar componentes DOM do desktop; compartilhar tokens/spacing/radius/typography/
  states/semântica de componente/linguagem de interação → visual ≈ desktop, arquitetura ≠.
- IA: Servers → Channels → Conversation (fluxo simples, sem drawers complexos do Discord).
- Call: tela dedicada; grid responsivo; barra compacta de call ao navegar para superfície
  compatível; respeitar padrões nativos (gestos, back, bottom sheets).
- Push genérico opt-in: "New activity on JanjaCord" — sem conteúdo/sender/server/channel.
- Efemeridade igual ao desktop: mensagens consumidas não reaparecem; sem read receipts.

## 3. Open decisions

- Navegação: bottom tabs (Servers/Channels) vs stack com listas: fluxo Servers → Channels →
  Conversation; call em tela dedicada (modal/full-screen); decidir no design system.
  Owner: design-ui-ux-designer (gate). Blocking: implementação mobile apenas.
- Permissões (mic/camera/notifications): pedir em contexto (Android 13+ POST_NOTIFICATIONS
  desligado por padrão; iOS pede por permission); fluxo de denied state com instrução clara.
- Tema: sincronizar com desktop (dark default).

## 4. Real behavior contract

### Telas/estados obrigatórios (V1 mobile)

1. **Onboarding**: Welcome → nickname + senha → Create identity → recovery key (uma vez, export);
   alternativa: Link existing identity (scan QR do desktop).
2. **Servers**: lista de servers (nome + estado); `+` add/create; empty state com CTA.
3. **Channels**: lista flat (# text, 🔊 call); unread indicators.
4. **Conversation**: header com nome do canal/server; mensagens da sessão; composer com
   anexo (imagem/arquivo) e share; menu por mensagem: Reply, Copy; imagem: Save/Share;
   arquivo: Download/Share; reactions inline.
5. **Call**: tela dedicada; tiles (video real vs avatar+nome); controles mic/camera/deafen/leave;
   barra compacta de call ao navegar; join states (permissão/lotado/host offline).
6. **Settings**: devices (lista/revogar), push preference (Off/Generic), server settings
   conforme permissão (retention, privacy mode), membership, invites.
7. **Estados**: empty, loading, error, denied permission, banned, expired invite, reconnect,
   attachment failure, relay/direct quando útil.

### Regras de UX

- Gestos nativos (back, swipe); bottom sheets para menus longos; inputs grandes (thumb-friendly).
- Feedback imediato de envio; retry visível em falha de entrega.
- Push preference explicada ("Notificações genéricas — sem conteúdo").
- Background/foreground: ao voltar, estado sincroniza; mensagens pendentes drenam; consumidas
  não reaparecem.

## 5. Required states and failures

- Loading: boot, sync, join.
- Empty: sem servers; canal vazio.
- Error: host offline (badge), TURN down, push falhou (sem conteúdo mesmo assim).
- Invalid input: invite malformado.
- Unauthorized: canal privado; banido (tela clara, sem retry loop).
- Slow dependency: network lenta (spinner de join/drain).
- Partial failure: attachment parcial → retry.
- Retry/recovery: reconnect automático; background → foreground preserva sessão;
  crash → reabre sem re-apresentar consumidas.

## 6. Acceptance criteria

- [ ] Fluxo Servers → Channels → Conversation completo com back nativo
- [ ] Device linking: mobile escaneia QR do desktop e vira a mesma identidade
- [ ] Call dedicada com grid responsivo e controles completos; barra compacta ao navegar
- [ ] Push: preferência Off/Generic funciona; payload nunca contém conteúdo
- [ ] Mensagens consumidas não reaparecem (efemeridade idêntica ao desktop)
- [ ] Visual ≈ desktop (tokens compartilhados); sem componente DOM
- [ ] Permissões pedidas em contexto; denied state com instrução
- [ ] Screenshots (Android+iOS) por fluxo material como evidence gate

## 7. Mock and placeholder policy

- Allowed only as internal draft: wireframes.
- Explicitly blocked for final: transporte/E2EE fake; push fake.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: nenhum mock.

## 8. Client/public language gate

- Terms that must not appear: "spool", "epoch", "envelope", termos de harness.
- Claims that require proof: n/a.
- Buyer/client language replacements: linguagem simples de produto.

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- UI-UX-EVIDENCE mobile (Android + iOS screenshots)
- Native smoke: device linking, call, push genérico real
- Review de design antes de release

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fases mobile
- Item(s): onboarding, servers/channels, conversation, call, push, devices
- Acceptance rule: `[x]` com screenshots + native smoke
- Evidence links: UI-UX-EVIDENCE; OPERATOR-TEST-PACKET

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (RN/expo; secure storage; push)
- INTEGRATIONS.md: sim (APNs/FCM/secure storage)
- ADR required: ADR-009 (Electron + RN) cobre a divisão
- Operator packet required: sim
