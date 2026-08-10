# SPEC — Desktop UI/UX Contract

## 1. Slice identity

- Slice / feature / artifact: contrato de UI/UX do desktop (Electron)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `apps/desktop` (futuro)
- Product truth source: PRODUCT.md §2 (Plataformas; UI), contrato congelado §45-§49
- Architecture truth source: ARCHITECTURE.md (Electron main/renderer/preload boundary)
- Checklist phase/item: fases desktop (onboarding → chat → call)
- Primary actor / audience: usuário desktop (Windows/macOS/Linux)
- Final-user outcome: app de comunicação privada moderna, densa e clara — não um clone do Discord
- Why this matters now: gate de UI/UX antes de qualquer frontend

## 2. Confirmed facts

- Stack: Electron + React + TypeScript + Vite + Tailwind + **shadcn/ui de verdade** (código dos
  componentes no projeto, controle integral da UI).
- Linguagem visual: moderna, limpa, minimalista, densa quando necessário, ótimos estados,
  dropdowns/dialogs claros, command-like efficiency, excelente dark mode, tipografia limpa,
  spacing consistente.
- NÃO copiar visualmente o Discord. NÃO estética hacker/cyberpunk/terminal verde. Nenhum
  placeholder/filler. Nada de "template feel".
- IA: server rail (esquerda) + channel list + conversation/call; member list NÃO permanente
  (drawer/popover no header); barra inferior com identidade/mic/deafen/settings.
- Call UI em tela dedicada com grid responsivo; controles mic/camera/deafen/leave.
- Efemeridade: ao sair do canal, mensagens consumidas não reaparecem; nenhum read receipt visível.

## 3. Open decisions

- Tema padrão: dark default com light opcional (produto de comunicação privada noturna);
  seguir sistema quando possível; decidir no design system (design tokens).
- Server rail: texto (abreviações "JD"/"XX") vs ícone: texto em monograma; tooltip com nome.
- Paleta: derivar de shadcn/ui neutros + um accent; definir tokens em `design-tokens` package.
  Owner: design-ui-ux-designer (gate). Blocking: não para arquitetura; sim para implementação.

## 4. Real behavior contract

### Telas/estados obrigatórios (V1 desktop)

1. **Onboarding / identity**: Welcome → nickname + senha → Create identity → recovery key
   (mostrada UMA vez, com export); já tenho conta → recovery/import.
2. **Device linking**: Settings → Devices → Add device → QR (desktop mostra, mobile escaneia);
   listar devices com revogação.
3. **Server rail**: monogramas + `+` (Add server / Create server); tooltip; badge de call ativa.
4. **Add server**: campo Invite key (JC1-…); validação em tempo real; erro de invite claro.
5. **Channel list**: flat (sem categories); # text com ícone; 🔊 call; indicadores de unread/
   call ativa; criação de canal conforme permissão.
6. **Conversation (texto)**: mensagens da sessão; nome do autor (nickname server-specific);
   menu `...` por mensagem: Reply, Copy; imagem: Save/Copy; arquivo: Download; reactions
   (👍 😂) inline com contagem; composer com anexo de imagem/arquivo; envio.
7. **Empty/error states**: sem servers; canal vazio; permissão negada; host offline;
   invite expirado/revogado; banido; attachment falhou; reconnect.
8. **Members**: drawer/popover no header (não permanente): lista, roles, kick/ban (conforme
   permissão), promote replica (owner).
9. **Server settings**: políticas (max retention, network privacy mode, TURN config),
   invites management, roles/permissions editor, ownership transfer, replicas.
10. **Call UI**: canal call selecionado → tela de call; grid responsivo de tiles (vídeo =
     tile real; sem câmera = avatar/nickname + mic state); controles mic/camera/deafen/leave;
     indicação de relay/direct quando útil; estados de join (permissão, lotado, host offline).
11. **Bottom bar**: identidade atual (nickname + device), mic, deafen, settings; call state.

### Regras de UX

- Composer sempre visível no canal de texto; sem typing indicator; sem read receipts visíveis.
- Feedback imediato de envio (estado local até ACK de entrega); erro de entrega com retry.
- Dark mode excelente por padrão; contraste AA; foco visível; teclado operável.
- Janela de call não bloqueia navegação (barra compacta ao navegar para outro canal compatível).

## 5. Required states and failures

- Loading: boot, sync de state, join de call.
- Empty: sem servers (CTA create/join), canal vazio (explicar efemeridade? evitar sobre-explicar).
- Error: host offline (badge + estado read-only onde aplicável), TURN down, purge aguardando.
- Invalid input: invite malformado; senha fraca no onboarding.
- Unauthorized: canal privado sem view; banido (tela de banido, sem retry automático).
- Slow dependency: STUN/TURN lento (spinner de join).
- Partial failure: envio sem ACK → estado "enviando/retry".
- Retry/recovery: reconnect automático com estado preservado; call reconecta com mesma policy.

## 6. Acceptance criteria

- [ ] Onboarding cria identidade e mostra recovery key uma única vez (fluxo real)
- [ ] Server rail + channel list + conversation navegáveis por teclado (focus visível)
- [ ] Member list não é permanente; abre no header
- [ ] Mensagem consumida não reaparece ao voltar ao canal (efemeridade visível)
- [ ] Call grid responsivo (1..6+ tiles) com controles mic/camera/deafen/leave
- [ ] Nenhum read receipt, typing indicator ou last seen na UI
- [ ] Dark mode de alta qualidade; sem placeholder copy; sem estética hacker
- [ ] Todos os estados da seção 5 renderizam com linguagem visual consistente
- [ ] Screenshot/Playwright de cada fluxo material (evidence gate antes de release)

## 7. Mock and placeholder policy

- Allowed only as internal draft: wireframes/mocks em exploração de design.
- Explicitly blocked for final: comportamento simulado (transporte/E2EE fake).
- Label required if mock remains: `MOCK`.
- Follow-up required before release: nenhum mock; copy real em todos os estados.

## 8. Client/public language gate

- Audience: usuário final (open-source).
- Terms that must not appear: "audience snapshot", "spool", "epoch", termos de harness.
- Claims that require proof: n/a (UI).
- Buyer/client language replacements: linguagem simples de produto ("Suas mensagens somem
  depois de lidas por todos", "Apenas convites").

## 9. (não aplicável — sem landing; aplicar quando houver superfície pública)

## 10. Evidence required before checklist completion

- UI-UX-EVIDENCE por fluxo (screenshots)
- Playwright smoke dos fluxos principais (desktop roda)
- Review de design (design-ui-ux-designer) antes de frontend final

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fases desktop
- Item(s): onboarding, rail, channels, conversation, call, settings
- Acceptance rule: `[x]` com screenshot/Playwright + review de design
- Evidence links: UI-UX-EVIDENCE-<id>; reviews

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (Electron boundary)
- INTEGRATIONS.md: não
- ADR required: ADR-010 (shadcn design language) já previsto
- Operator packet required: sim (milestones desktop)
